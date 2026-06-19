#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <elf.h>
#include <string>
#include <vector>

#define TAG "ssl_kill_switch"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ─── Safe memory write ────────────────────────────────────────────────────────
//
// Android 10+ enforces W^X: mprotect(PROT_WRITE|PROT_EXEC) on r-x pages fails
// with EACCES (SELinux / kernel policy). Frida bypasses this via /proc/self/mem
// which writes directly to physical pages without changing protection bits.
// We do the same: try /proc/self/mem first, fall back to mprotect for old kernels.

static bool mem_write(void* addr, const void* src, size_t n) {
    // Primary path: /proc/self/mem — bypasses W^X, always writable by own process
    int fd = open("/proc/self/mem", O_RDWR);
    if (fd >= 0) {
        ssize_t written = pwrite64(fd, src, n, static_cast<off64_t>(
            reinterpret_cast<uintptr_t>(addr)));
        close(fd);
        if (written == static_cast<ssize_t>(n)) {
            __builtin___clear_cache(static_cast<char*>(addr),
                                    static_cast<char*>(addr) + n);
            return true;
        }
        LOGE("mem_write: pwrite64 failed @ %p (written=%zd errno=%d)", addr, written, errno);
    }

    // Fallback: mprotect (works on Android < 10 or without strict W^X policy)
    long ps = sysconf(_SC_PAGE_SIZE);
    uintptr_t pg = reinterpret_cast<uintptr_t>(addr) & ~static_cast<uintptr_t>(ps - 1);
    if (mprotect(reinterpret_cast<void*>(pg), static_cast<size_t>(ps) * 2,
                 PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("mem_write: mprotect failed @ %p (errno=%d)", addr, errno);
        return false;
    }
    memcpy(addr, src, n);
    mprotect(reinterpret_cast<void*>(pg), static_cast<size_t>(ps) * 2,
             PROT_READ | PROT_EXEC); // restore W^X
    __builtin___clear_cache(static_cast<char*>(addr),
                            static_cast<char*>(addr) + n);
    return true;
}

// ─── ARM64 inline hook (LDR X16, #8 ; BR X16 ; <8-byte addr>) ───────────────

static bool write_trampoline(void* target, void* replacement) {
    if (!target || !replacement) return false;

    uint32_t stub[4];
    stub[0] = 0x58000050u; // LDR X16, #8
    stub[1] = 0xD61F0200u; // BR X16
    *reinterpret_cast<uint64_t*>(&stub[2]) = reinterpret_cast<uint64_t>(replacement);

    if (!mem_write(target, stub, sizeof(stub))) {
        LOGE("write_trampoline failed %p -> %p", target, replacement);
        return false;
    }
    LOGI("Hooked %p -> %p", target, replacement);
    return true;
}

// ─── ELF symbol resolver via /proc/self/maps ─────────────────────────────────

struct MapEntry { uintptr_t base; std::string name; };

static std::vector<MapEntry> get_maps() {
    std::vector<MapEntry> result;
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return result;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        uintptr_t start, end;
        char perms[8], path[256] = {};
        unsigned long offset; int maj, min; unsigned long inode;
        if (sscanf(line, "%lx-%lx %4s %lx %x:%x %lu %255s",
                   &start, &end, perms, &offset, &maj, &min, &inode, path) >= 7) {
            if (offset == 0 && perms[0] == 'r' && path[0] == '/')
                result.push_back({start, path});
        }
    }
    fclose(f);
    return result;
}

static void* find_symbol_elf(uintptr_t base, const char* sym_name) {
    auto* ehdr = reinterpret_cast<Elf64_Ehdr*>(base);
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) return nullptr;

    auto* phdr = reinterpret_cast<Elf64_Phdr*>(base + ehdr->e_phoff);
    const Elf64_Dyn* dyn = nullptr;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dyn = reinterpret_cast<const Elf64_Dyn*>(base + phdr[i].p_vaddr);
            break;
        }
    }
    if (!dyn) return nullptr;

    const Elf64_Sym* sym_table = nullptr;
    const char* str_table = nullptr;
    size_t sym_count = 0;

    for (const Elf64_Dyn* d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
            case DT_SYMTAB: sym_table = reinterpret_cast<const Elf64_Sym*>(base + d->d_un.d_ptr); break;
            case DT_STRTAB: str_table = reinterpret_cast<const char*>(base + d->d_un.d_ptr); break;
            case DT_HASH: sym_count = reinterpret_cast<const uint32_t*>(base + d->d_un.d_ptr)[1]; break;
            case DT_GNU_HASH: {
                auto* g = reinterpret_cast<const uint32_t*>(base + d->d_un.d_ptr);
                uint32_t nb = g[0], sym_off = g[1], bloom = g[2];
                const uint32_t* bkt = g + 4 + bloom * 2;
                const uint32_t* chn = bkt + nb;
                uint32_t last = 0;
                for (uint32_t i = 0; i < nb; i++) if (bkt[i] > last) last = bkt[i];
                if (last >= sym_off) {
                    uint32_t idx = last - sym_off;
                    while (!(chn[idx] & 1)) idx++;
                    sym_count = last + 1;
                }
                break;
            }
            default: break;
        }
    }
    if (!sym_table || !str_table || sym_count == 0) return nullptr;

    for (size_t i = 0; i < sym_count; i++) {
        const Elf64_Sym& s = sym_table[i];
        if (s.st_value && strcmp(str_table + s.st_name, sym_name) == 0)
            return reinterpret_cast<void*>(base + s.st_value);
    }
    return nullptr;
}

static void* find_symbol_in_maps(const char* lib_substr, const char* sym_name) {
    for (const auto& e : get_maps()) {
        if (e.name.find(lib_substr) != std::string::npos) {
            void* a = find_symbol_elf(e.base, sym_name);
            if (a) { LOGI("Found %s in %s @ %p", sym_name, e.name.c_str(), a); return a; }
        }
    }
    return nullptr;
}

// ─── Symbol-based SSL hooks ───────────────────────────────────────────────────

typedef void SSL_CTX; typedef void SSL; typedef void X509_STORE_CTX;
typedef int  (*SSL_CTX_set_verify_fn)(SSL_CTX*, int, void*);
typedef void (*SSL_CTX_set_custom_verify_fn)(SSL_CTX*, int, int(*)(SSL*, uint8_t*));
typedef long (*SSL_get_verify_result_fn)(const SSL*);
typedef int  (*X509_verify_cert_fn)(X509_STORE_CTX*);
typedef SSL_CTX* (*SSL_CTX_new_fn)(const void*);

static SSL_CTX_new_fn               orig_SSL_CTX_new              = nullptr;
static SSL_CTX_set_verify_fn        orig_SSL_CTX_set_verify        = nullptr;
static SSL_CTX_set_custom_verify_fn orig_SSL_CTX_set_custom_verify = nullptr;

static int hooked_verify_callback(SSL*, uint8_t*) { return 0; }

static SSL_CTX* hooked_SSL_CTX_new(const void* method) {
    SSL_CTX* ctx = orig_SSL_CTX_new(method);
    if (ctx && orig_SSL_CTX_set_verify) orig_SSL_CTX_set_verify(ctx, 0, nullptr);
    if (ctx && orig_SSL_CTX_set_custom_verify)
        orig_SSL_CTX_set_custom_verify(ctx, 0, hooked_verify_callback);
    return ctx;
}
static void hooked_SSL_CTX_set_custom_verify(SSL_CTX* ctx, int, int(*)(SSL*, uint8_t*)) {
    if (orig_SSL_CTX_set_custom_verify)
        orig_SSL_CTX_set_custom_verify(ctx, 0, hooked_verify_callback);
}
static long hooked_SSL_get_verify_result(const SSL*) { return 0; }
static int  hooked_X509_verify_cert(X509_STORE_CTX*)  { return 1; }

static void try_hook_in_lib(const char* lib_substr) {
    void* h = dlopen(lib_substr, RTLD_NOW | RTLD_NOLOAD);
    auto resolve = [&](const char* sym) -> void* {
        void* a = h ? dlsym(h, sym) : nullptr;
        if (!a) a = find_symbol_in_maps(lib_substr, sym);
        if (!a) a = dlsym(RTLD_DEFAULT, sym);
        return a;
    };
    if (void* t = resolve("SSL_CTX_new")) {
        orig_SSL_CTX_new = reinterpret_cast<SSL_CTX_new_fn>(t);
        write_trampoline(t, reinterpret_cast<void*>(hooked_SSL_CTX_new));
    }
    if (void* t = resolve("SSL_CTX_set_verify"))
        orig_SSL_CTX_set_verify = reinterpret_cast<SSL_CTX_set_verify_fn>(t);
    if (void* t = resolve("SSL_CTX_set_custom_verify")) {
        orig_SSL_CTX_set_custom_verify = reinterpret_cast<SSL_CTX_set_custom_verify_fn>(t);
        write_trampoline(t, reinterpret_cast<void*>(hooked_SSL_CTX_set_custom_verify));
    }
    if (void* t = resolve("SSL_get_verify_result"))
        write_trampoline(t, reinterpret_cast<void*>(hooked_SSL_get_verify_result));
    if (void* t = resolve("X509_verify_cert"))
        write_trampoline(t, reinterpret_cast<void*>(hooked_X509_verify_cert));
    if (h) dlclose(h);
}

// ─── Flutter: pattern-based ssl_verify_peer_cert bypass ──────────────────────
//
// Flutter statically links BoringSSL — no exported symbols, dlsym always fails.
// Pattern-scan the r-x pages of libflutter.so for ssl_verify_peer_cert prologue,
// then patch it to return 0 (ssl_verify_ok) unconditionally.
//
// Called from Java via JNI after System.loadLibrary("flutter") fires, so
// libflutter.so is guaranteed to be mapped at this point.
//
// Patterns: https://github.com/NVISOsecurity/disable-flutter-tls-verification

struct PatternByte { uint8_t value, mask; };

static bool hex_nibble(char c, uint8_t& o) {
    if (c>='0'&&c<='9'){o=(uint8_t)(c-'0');return true;}
    if (c>='a'&&c<='f'){o=(uint8_t)(c-'a'+10);return true;}
    if (c>='A'&&c<='F'){o=(uint8_t)(c-'A'+10);return true;}
    return false;
}

static std::vector<PatternByte> parse_pattern(const char* s) {
    std::vector<PatternByte> out;
    while (*s) {
        while (*s==' ') s++;
        if (!*s) break;
        PatternByte pb={0,0}; uint8_t n;
        if (*s=='?') s++; else if (hex_nibble(*s++,n)){pb.value|=(uint8_t)(n<<4);pb.mask|=0xF0;}
        if (*s=='?') s++; else if (hex_nibble(*s++,n)){pb.value|=n;pb.mask|=0x0F;}
        out.push_back(pb);
    }
    return out;
}

static const uint8_t* scan_pattern(const uint8_t* data, size_t size,
                                    const std::vector<PatternByte>& pat) {
    if (pat.empty() || size < pat.size()) return nullptr;
    size_t lim = size - pat.size();
    for (size_t i = 0; i <= lim; i++) {
        bool ok = true;
        for (size_t j = 0; j < pat.size(); j++)
            if ((data[i+j] & pat[j].mask) != pat[j].value) { ok=false; break; }
        if (ok) return data+i;
    }
    return nullptr;
}

struct MemRange { uintptr_t base; size_t size; };

// pkg_filter: when non-null, only include paths also containing the package name.
// This scopes libflutter.so scanning to the target app's own .apk installation path.
static std::vector<MemRange> get_rx_ranges(const char* lib, const char* pkg_filter = nullptr) {
    std::vector<MemRange> r;
    FILE* f = fopen("/proc/self/maps","r");
    if (!f) return r;
    char line[512];
    while (fgets(line,sizeof(line),f)) {
        uintptr_t s,e; char p[8],path[256]={};
        unsigned long off; int maj,min; unsigned long ino;
        if (sscanf(line,"%lx-%lx %4s %lx %x:%x %lu %255s",&s,&e,p,&off,&maj,&min,&ino,path)>=7) {
            bool libOk = strstr(path, lib) != nullptr;
            bool pkgOk = !pkg_filter || strstr(path, pkg_filter) != nullptr;
            if (p[2]=='x' && libOk && pkgOk) r.push_back({s, e-s});
        }
    }
    fclose(f);
    return r;
}

// Patch ssl_verify_peer_cert to unconditionally return ssl_verify_ok (0).
// Mirrors Frida's: Interceptor.replace(addr, new NativeCallback(() => 0, 'int', ['pointer','int']))
// Uses mem_write (proc/self/mem first) to bypass Android 10+ W^X.
static bool patch_return_zero(void* addr) {
#if defined(__aarch64__)
    // MOV W0, #0  (ssl_verify_ok)
    // RET
    const uint32_t ins[2] = { 0x52800000u, 0xD65F03C0u };
    const size_t   sz     = sizeof(ins);
#elif defined(__arm__)
    // MOVS R0, #0 ; BX LR
    const uint8_t  ins[4] = { 0x00, 0x20, 0x70, 0x47 };
    const size_t   sz     = sizeof(ins);
#elif defined(__x86_64__)
    // XOR EAX, EAX ; RET
    const uint8_t  ins[3] = { 0x31, 0xC0, 0xC3 };
    const size_t   sz     = sizeof(ins);
#else
    LOGE("Flutter: patch_return_zero: unsupported arch"); return false;
#endif
    if (!mem_write(addr, ins, sz)) {
        LOGE("Flutter: patch_return_zero failed @ %p", addr);
        return false;
    }
    LOGI("Flutter: patched ssl_verify_peer_cert @ %p (%zu bytes)", addr, sz);
    return true;
}

static const char* FLUTTER_PAT_ARM64[] = {
    "F? 0F 1C F8 F? 5? 01 A9 F? 5? 02 A9 F? ?? 03 A9 ?? ?? ?? ?? 68 1A 40 F9",
    "F? 43 01 D1 FE 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 13 00 40 F9 F4 03 00 AA 68 1A 40 F9",
    "FF 43 01 D1 FE 67 01 A9 ?? ?? 06 94 ?? 7? 06 94 68 1A 40 F9 15 15 41 F9 B5 00 00 B4 B6 4A 40 F9",
};
static const char* FLUTTER_PAT_ARM[] = {
    "2D E9 F? 4? D0 F8 00 80 81 46 D8 F8 18 00 D0 F8",
};
static const char* FLUTTER_PAT_X64[] = {
    "55 41 57 41 56 41 55 41 54 53 50 49 89 f? 4? 8b ?? 4? 8b 4? 30 4c 8b ?? ?? 0? 00 00 4d 85 ?? 74 1? 4d 8b",
    "55 41 57 41 56 41 55 41 54 53 48 83 EC 18 49 89 FF 48 8B 1F 48 8B 43 30 4C 8B A0 28 02 00 00 4D 85 E4 74",
};

static volatile bool s_flutter_patched = false;

// Scans libflutter.so r-x ranges for ssl_verify_peer_cert and patches it.
// pkg_filter: if non-null, only scan paths containing the package name (per-app targeting).
static bool try_patch_flutter(const char* pkg_filter = nullptr) {
    if (s_flutter_patched) return true;

    auto ranges = get_rx_ranges("libflutter.so", pkg_filter);
    if (ranges.empty()) {
        if (pkg_filter)
            LOGI("Flutter: libflutter.so not in maps for pkg=%s", pkg_filter);
        else
            LOGI("Flutter: libflutter.so not in maps yet");
        return false;
    }

    LOGI("Flutter: scanning %zu rx ranges", ranges.size());

#if defined(__aarch64__)
    const char** pats=FLUTTER_PAT_ARM64; size_t np=sizeof(FLUTTER_PAT_ARM64)/sizeof(*FLUTTER_PAT_ARM64); int th=0;
#elif defined(__arm__)
    const char** pats=FLUTTER_PAT_ARM;  size_t np=sizeof(FLUTTER_PAT_ARM)/sizeof(*FLUTTER_PAT_ARM);   int th=1;
#elif defined(__x86_64__)
    const char** pats=FLUTTER_PAT_X64;  size_t np=sizeof(FLUTTER_PAT_X64)/sizeof(*FLUTTER_PAT_X64);   int th=0;
#else
    LOGE("Flutter: unsupported arch"); return false;
#endif

    for (size_t pi=0; pi<np; pi++) {
        auto pat = parse_pattern(pats[pi]);
        for (const auto& r : ranges) {
            const uint8_t* hit = scan_pattern(reinterpret_cast<const uint8_t*>(r.base), r.size, pat);
            if (!hit) continue;
            void* tgt = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hit)+th);
            LOGI("Flutter: ssl_verify_peer_cert matched pattern[%zu] @ %p", pi, tgt);
            if (patch_return_zero(tgt)) {
                LOGI("Flutter: patched — TLS verification disabled");
                s_flutter_patched = true;
                return true;
            }
            LOGE("Flutter: patch failed @ %p", tgt);
        }
    }
    LOGE("Flutter: ssl_verify_peer_cert not found — patterns may need update");
    return false;
}

// ─── Main hook orchestrator ───────────────────────────────────────────────────

static void scan_and_hook() {
    // Symbol-based: system BoringSSL / OpenSSL, React Native
    try_hook_in_lib("libssl.so");
    try_hook_in_lib("libcrypto.so");
    try_hook_in_lib("librnssl.so");

    // RTLD_DEFAULT catches anything already linked
    if (void* t = dlsym(RTLD_DEFAULT, "SSL_CTX_set_custom_verify"))
        write_trampoline(t, reinterpret_cast<void*>(hooked_SSL_CTX_set_custom_verify));
    if (void* t = dlsym(RTLD_DEFAULT, "SSL_get_verify_result"))
        write_trampoline(t, reinterpret_cast<void*>(hooked_SSL_get_verify_result));
    if (void* t = dlsym(RTLD_DEFAULT, "X509_verify_cert"))
        write_trampoline(t, reinterpret_cast<void*>(hooked_X509_verify_cert));

    // Flutter: pattern-scan (only succeeds if libflutter.so is already mapped)
    try_patch_flutter();
}

// ─── JNI entry points ─────────────────────────────────────────────────────────

extern "C" JNIEXPORT void JNICALL
Java_com_horizon_sslkillswitch_hooks_NativeHooks_nativeScanAndHook(JNIEnv*, jclass) {
    LOGI("nativeScanAndHook");
    scan_and_hook();
}

// Called specifically after System.loadLibrary("flutter") — libflutter.so guaranteed mapped.
extern "C" JNIEXPORT void JNICALL
Java_com_horizon_sslkillswitch_hooks_NativeHooks_nativePatchFlutter(JNIEnv*, jclass) {
    LOGI("nativePatchFlutter");
    try_patch_flutter();
}

// pkg-scoped variant: restricts libflutter.so search to paths containing the package name.
// Avoids false-positive matches if multiple Flutter apps are loaded in the same zygote fork.
extern "C" JNIEXPORT void JNICALL
Java_com_horizon_sslkillswitch_hooks_NativeHooks_nativePatchFlutterForPkg(JNIEnv* env, jclass, jstring jpkg) {
    const char* pkg = env->GetStringUTFChars(jpkg, nullptr);
    LOGI("[%s] nativePatchFlutterForPkg", pkg);
    try_patch_flutter(pkg);
    env->ReleaseStringUTFChars(jpkg, pkg);
}
