#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <elf.h>
#include <string>
#include <vector>

#define TAG "ssl_kill_switch"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ─── ARM64 inline hook ────────────────────────────────────────────────────────
// Trampoline: LDR X16, #8 (0x58000050) ; BR X16 (0xD61F0200) ; <8-byte address>
// Total: 16 bytes. Overwrites the first 16 bytes of the target function.

static bool write_trampoline(void* target, void* replacement) {
    if (!target || !replacement) return false;

    long page_size = sysconf(_SC_PAGE_SIZE);
    uintptr_t page_start = reinterpret_cast<uintptr_t>(target) & ~(page_size - 1);

    if (mprotect(reinterpret_cast<void*>(page_start), page_size * 2,
                 PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("mprotect failed for %p", target);
        return false;
    }

    uint32_t* p = reinterpret_cast<uint32_t*>(target);
    p[0] = 0x58000050u; // LDR X16, #8
    p[1] = 0xD61F0200u; // BR X16
    uint64_t* addr = reinterpret_cast<uint64_t*>(p + 2);
    *addr = reinterpret_cast<uint64_t>(replacement);

    __builtin___clear_cache(reinterpret_cast<char*>(target),
                            reinterpret_cast<char*>(target) + 16);
    LOGI("Hooked %p -> %p", target, replacement);
    return true;
}

// ─── ELF symbol resolver ─────────────────────────────────────────────────────
// Finds a symbol in a mapped library by walking its ELF dynamic symbol table.

struct MapEntry {
    uintptr_t base;
    std::string name;
};

static std::vector<MapEntry> get_maps() {
    std::vector<MapEntry> result;
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return result;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        uintptr_t start, end;
        char perms[8], path[256] = {};
        unsigned long offset;
        int dev_major, dev_minor;
        unsigned long inode;
        if (sscanf(line, "%lx-%lx %4s %lx %x:%x %lu %255s",
                   &start, &end, perms, &offset,
                   &dev_major, &dev_minor, &inode, path) >= 7) {
            // Only record executable, non-zero-offset base mappings
            if (offset == 0 && perms[0] == 'r' && path[0] == '/') {
                result.push_back({start, path});
            }
        }
    }
    fclose(f);
    return result;
}

static void* find_symbol_elf(uintptr_t base, const char* sym_name) {
    auto* ehdr = reinterpret_cast<Elf64_Ehdr*>(base);
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) return nullptr;

    auto* phdr = reinterpret_cast<Elf64_Phdr*>(base + ehdr->e_phoff);

    // Find PT_DYNAMIC segment
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
            case DT_HASH: {
                // GNU hash not handled; fallback to DT_HASH nchain
                auto* hash = reinterpret_cast<const uint32_t*>(base + d->d_un.d_ptr);
                sym_count = hash[1]; // nchain == symbol count
                break;
            }
            case DT_GNU_HASH: {
                auto* gnu = reinterpret_cast<const uint32_t*>(base + d->d_un.d_ptr);
                uint32_t nbuckets = gnu[0];
                uint32_t sym_offset = gnu[1];
                uint32_t bloom_size = gnu[2];
                const uint32_t* buckets = gnu + 4 + (bloom_size * 2);
                const uint32_t* chains = buckets + nbuckets;
                // Estimate sym count from last chain entry
                uint32_t last_bucket = 0;
                for (uint32_t i = 0; i < nbuckets; i++)
                    if (buckets[i] > last_bucket) last_bucket = buckets[i];
                if (last_bucket >= sym_offset) {
                    uint32_t idx = last_bucket - sym_offset;
                    while (!(chains[idx] & 1)) idx++;
                    sym_count = last_bucket + 1;
                }
                break;
            }
            default: break;
        }
    }

    if (!sym_table || !str_table || sym_count == 0) return nullptr;

    for (size_t i = 0; i < sym_count; i++) {
        const Elf64_Sym& sym = sym_table[i];
        if (sym.st_value == 0) continue;
        const char* name = str_table + sym.st_name;
        if (strcmp(name, sym_name) == 0) {
            return reinterpret_cast<void*>(base + sym.st_value);
        }
    }
    return nullptr;
}

static void* find_symbol_in_maps(const char* lib_substr, const char* sym_name) {
    for (const auto& entry : get_maps()) {
        if (entry.name.find(lib_substr) != std::string::npos) {
            void* addr = find_symbol_elf(entry.base, sym_name);
            if (addr) {
                LOGI("Found %s in %s @ %p", sym_name, entry.name.c_str(), addr);
                return addr;
            }
        }
    }
    return nullptr;
}

// ─── Hook targets ─────────────────────────────────────────────────────────────

// BoringSSL / OpenSSL type aliases (opaque pointers — we don't need the full struct)
typedef void SSL_CTX;
typedef void SSL;
typedef void X509_STORE_CTX;

// ssl_verify_result_t enum values
#define ssl_verify_ok              0
#define ssl_verify_invalid         1
#define ssl_verify_retry           2

typedef int  (*SSL_CTX_set_verify_fn)(SSL_CTX*, int, void*);
typedef void (*SSL_CTX_set_custom_verify_fn)(SSL_CTX*, int, int(*)(SSL*, uint8_t*));
typedef long (*SSL_get_verify_result_fn)(const SSL*);
typedef int  (*X509_verify_cert_fn)(X509_STORE_CTX*);
typedef SSL_CTX* (*SSL_CTX_new_fn)(const void*);

static SSL_CTX_new_fn              orig_SSL_CTX_new              = nullptr;
static SSL_CTX_set_verify_fn       orig_SSL_CTX_set_verify       = nullptr;
static SSL_CTX_set_custom_verify_fn orig_SSL_CTX_set_custom_verify = nullptr;

// Replacement: accept all certs
static int hooked_verify_callback(SSL* /*ssl*/, uint8_t* /*out_alert*/) {
    return ssl_verify_ok;
}

// Hook SSL_CTX_new: on every new context, force verify none
static SSL_CTX* hooked_SSL_CTX_new(const void* method) {
    SSL_CTX* ctx = orig_SSL_CTX_new(method);
    if (ctx && orig_SSL_CTX_set_verify)
        orig_SSL_CTX_set_verify(ctx, 0 /*SSL_VERIFY_NONE*/, nullptr);
    if (ctx && orig_SSL_CTX_set_custom_verify)
        orig_SSL_CTX_set_custom_verify(ctx, 0, hooked_verify_callback);
    return ctx;
}

// Hook SSL_CTX_set_custom_verify: replace any user callback with ours
static void hooked_SSL_CTX_set_custom_verify(SSL_CTX* ctx, int mode,
                                              int (*/*cb*/)(SSL*, uint8_t*)) {
    // Ignore user callback — always install the permissive one
    if (orig_SSL_CTX_set_custom_verify)
        orig_SSL_CTX_set_custom_verify(ctx, 0, hooked_verify_callback);
}

// Hook SSL_get_verify_result: always return X509_V_OK (0)
static long hooked_SSL_get_verify_result(const SSL* /*ssl*/) {
    return 0; // X509_V_OK
}

// Hook X509_verify_cert: always succeed
static int hooked_X509_verify_cert(X509_STORE_CTX* /*ctx*/) {
    return 1;
}

// ─── Hook installation ────────────────────────────────────────────────────────

static void try_hook_in_lib(const char* lib_substr) {
    void* handle = dlopen(lib_substr, RTLD_NOW | RTLD_NOLOAD);

    auto resolve = [&](const char* sym) -> void* {
        void* addr = nullptr;
        if (handle) addr = dlsym(handle, sym);
        if (!addr) addr = find_symbol_in_maps(lib_substr, sym);
        if (!addr) addr = dlsym(RTLD_DEFAULT, sym);
        return addr;
    };

    // SSL_CTX_new
    if (void* target = resolve("SSL_CTX_new")) {
        orig_SSL_CTX_new = reinterpret_cast<SSL_CTX_new_fn>(target);
        write_trampoline(target, reinterpret_cast<void*>(hooked_SSL_CTX_new));
    }

    // SSL_CTX_set_verify (used to disable verify mode)
    if (void* target = resolve("SSL_CTX_set_verify")) {
        orig_SSL_CTX_set_verify = reinterpret_cast<SSL_CTX_set_verify_fn>(target);
        // Don't hook this one — we call the original from hooked_SSL_CTX_new
    }

    // SSL_CTX_set_custom_verify
    if (void* target = resolve("SSL_CTX_set_custom_verify")) {
        orig_SSL_CTX_set_custom_verify =
            reinterpret_cast<SSL_CTX_set_custom_verify_fn>(target);
        write_trampoline(target, reinterpret_cast<void*>(hooked_SSL_CTX_set_custom_verify));
    }

    // SSL_get_verify_result
    if (void* target = resolve("SSL_get_verify_result")) {
        write_trampoline(target, reinterpret_cast<void*>(hooked_SSL_get_verify_result));
    }

    // X509_verify_cert
    if (void* target = resolve("X509_verify_cert")) {
        write_trampoline(target, reinterpret_cast<void*>(hooked_X509_verify_cert));
    }

    if (handle) dlclose(handle);
}

static void scan_and_hook() {
    // System SSL (non-Flutter apps using Android's BoringSSL via Conscrypt JNI)
    try_hook_in_lib("libssl.so");
    try_hook_in_lib("libcrypto.so");

    // Flutter (BoringSSL statically linked in libflutter.so)
    try_hook_in_lib("libflutter.so");

    // React Native / custom embeds
    try_hook_in_lib("librnssl.so");
    try_hook_in_lib("libc++_shared.so");

    // Also try RTLD_DEFAULT (catches anything already linked)
    {
        auto resolve_global = [](const char* sym) -> void* {
            return dlsym(RTLD_DEFAULT, sym);
        };

        if (void* t = resolve_global("SSL_CTX_set_custom_verify"))
            write_trampoline(t, reinterpret_cast<void*>(hooked_SSL_CTX_set_custom_verify));

        if (void* t = resolve_global("SSL_get_verify_result"))
            write_trampoline(t, reinterpret_cast<void*>(hooked_SSL_get_verify_result));

        if (void* t = resolve_global("X509_verify_cert"))
            write_trampoline(t, reinterpret_cast<void*>(hooked_X509_verify_cert));
    }
}

// ─── JNI entry point ──────────────────────────────────────────────────────────

extern "C" JNIEXPORT void JNICALL
Java_com_horizon_sslkillswitch_hooks_NativeHooks_nativeScanAndHook(JNIEnv*, jclass) {
    LOGI("nativeScanAndHook called");
    scan_and_hook();
}
