# SSL Kill Switch — LSPosed Module

LSPosed module for disabling SSL certificate pinning on Android. Covers Java-layer pinning (OkHttp, TrustManager, Conscrypt, WebView, Cordova, Tencent X5) and native-layer pinning (BoringSSL embedded in Flutter, React Native, and other NDK-based apps).

## Features

- **Java SSL bypass**: X509TrustManager, HostnameVerifier, OkHttp CertificatePinner (v3/v4), TrustKit, Conscrypt, WebViewClient
- **WebView bypass**: `onReceivedSslError` → `handler.proceed()`; `SslErrorHandler.cancel()` redirected to `proceed()` catching all subclass overrides; `onReceivedError` suppressed; Cordova and Tencent X5 WebView fully covered
- **Flutter native bypass (Kotlin mode)**: pattern-scan `ssl_verify_peer_cert` prologue in `libflutter.so`, copy + patch return-0 stub, load patched lib before original; handles `extractNativeLibs=false` (APK-embedded libs) via ZipFile extraction
- **Native SSL bypass**: BoringSSL inline hooks via ARM64 trampoline — covers React Native and any app embedding BoringSSL/OpenSSL
- **Per-app scope**: enable hooks only for selected packages
- **Per-hook toggle**: TrustManager, OkHttp, WebView, Native independently per app
- **Domain filter**: optionally restrict bypass to specific hostnames
- **iptables redirect**: global and per-UID NAT rules forwarding app traffic to a proxy (Burp, mitmproxy); per-rule delete and flush-all from UI
- **Global logging toggle**: enable/disable Xposed log output from the Settings card
- Root required only for iptables rules; SSL bypass works without root via LSPosed scope

## Architecture

```
MainHook
├── IXposedHookZygoteInit.initZygote()       — fires in Zygote once, inherited by ALL processes
│   └── TrustManagerHooks.applySystem()      — hooks boot-classpath classes via system ClassLoader
│       ├── TrustManagerImpl (conscrypt)     — checkServerTrusted, checkTrustedRecursive, verifyChain
│       ├── HostnameVerifier                 — verify → always true
│       ├── SSLContext.init                  — replace TrustManagers with permissive impl
│       ├── ConscryptEngine/FileDescriptor   — verifyCertificateChain → no-op
│       └── NetworkSecurityTrustManager      — checkPins, checkServerTrusted → no-op
│
└── IXposedHookLoadPackage.handleLoadPackage() — fires per-process for all packages
    ├── TrustManagerHooks.apply(cl, pkg)     — re-applies with app classloader
    ├── OkHttpHooks.apply(cl, pkg)           — only if okhttp3.OkHttpClient in classloader
    ├── WebViewHooks.apply(cl, pkg)          — see WebView coverage below
    └── hookLoadLibraryKotlin(pkg, cl)       — Flutter bypass trigger
        ├── Runtime.loadLibrary0 (all variants: 2-param API 26-28, 3-param API 29+)
        ├── System.loadLibrary(String)       — fallback if loadLibrary0 not hookable
        └── System.load(String)             — catches embeddings that pass absolute path
            └── FlutterPatcher
                ├── findLibFlutterPath()    — ClassLoader.findLibrary → nativeLibraryDir → APK ZipFile scan
                ├── extractFromApk()        — extracts lib from APK when extractNativeLibs=false
                ├── patch()                 — pattern-scan prologue, write MOV W0,#0; RET stub
                └── loadPatched()           — 5-strategy loader: load0(Class), load0(CL), load(String,CL), nativeLoad, System.load
```

**Two-tier approach:**

| Tier | Scope | Mechanism | Requires selection? |
|------|-------|-----------|---------------------|
| Java SSL | All processes | Zygote boot-classpath + per-app classloader re-apply | No |
| Native SSL | Selected apps only | `ssl_kill_switch.so` load + inline trampoline patching | Yes (UI) |
| Flutter bypass | All processes | File patch + pre-load before original loadLibrary | No |

## Hook coverage

| Layer | Target | Method |
|-------|--------|--------|
| Java | `X509TrustManager.checkServerTrusted` | hook → no-op |
| Java | `X509TrustManager.checkClientTrusted` | hook → no-op |
| Java | `HostnameVerifier.verify` | hook → return true |
| Java | `OkHttpClient.Builder.build` | hook → strip CertificatePinner |
| Java | `CertificatePinner.check` / `check$okhttp` | hook → no-op |
| Java | `TrustManagerImpl.verifyChain` | hook → return input chain |
| Java | `SSLContext.init` | hook → inject permissive TrustManager |
| Java | `WebViewClient.onReceivedSslError` | hook → `handler.proceed()` |
| Java | `WebViewClientCompat.onReceivedSslError` | hook → `handler.proceed()` |
| Java | `WebViewClient.onReceivedError` (both variants) | hook → suppress |
| Java | `SslErrorHandler.cancel()` | hook → `proceed()` — catches subclasses that call cancel directly |
| Java | `CordovaWebViewClient.onReceivedSslError` | hook → smart proceed |
| Java | `cordova.engine.SystemWebViewClient.onReceivedSslError` | hook → smart proceed |
| Java | `com.tencent.smtt.sdk.WebViewClient.onReceivedSslError` | hook → smart proceed (X5 types) |
| Java | `com.tencent.smtt.sdk.SystemWebViewClient.onReceivedSslError` | hook → smart proceed |
| Java | `com.tencent.smtt.sdk.SystemWebViewClient.onReceivedError` | hook → suppress |
| Native | `SSL_CTX_new` | inline hook → set SSL_VERIFY_NONE |
| Native | `SSL_CTX_set_custom_verify` | inline hook → replace callback |
| Native | `SSL_get_verify_result` | inline hook → return X509_V_OK |
| Native | `X509_verify_cert` | inline hook → return 1 |
| Native | `ssl_verify_peer_cert` (Flutter) | pattern-scan + MOV W0,#0 ; RET patch |

## WebView bypass detail

Standard `WebViewClient.onReceivedSslError` hooks catch the base class and Compat variant. Apps that subclass `WebViewClient` and override `onReceivedSslError` without calling `super` are caught by the `SslErrorHandler.cancel()` redirect: any override that calls `handler.cancel()` (the default Android behavior) is intercepted and redirected to `proceed()` instead.

Smart proceed tries method names `proceed → continueLoad → continue → ignore` on the handler object, covering non-standard handler APIs in custom WebView SDKs.

## Flutter native bypass detail

`libflutter.so` statically links BoringSSL — no exported symbols, `dlsym` always fails. The Kotlin-mode bypass:

1. Hooks `Runtime.loadLibrary0` (all parameter variants), `System.loadLibrary`, and `System.load` to intercept the Flutter library load before it is mapped
2. Resolves the library path via `ClassLoader.findLibrary`, `nativeLibraryDir`, or direct APK ZipFile scan (required when `android:extractNativeLibs=false`, the default since AGP 4.2/Flutter SDK)
3. Extracts `libflutter.so` from the APK if it is embedded (APK-embedded path format: `base.apk!/lib/arm64-v8a/libflutter.so`)
4. Pattern-scans the extracted bytes for the `ssl_verify_peer_cert` function prologue
5. Writes a return-0 stub over the matched offset in a copy of the file
6. Loads the patched copy via a 5-strategy cascade before the original load proceeds

```
Patterns (ARM64):
  F? 0F 1C F8 F? 5? 01 A9 F? 5? 02 A9 F? ?? 03 A9 ?? ?? ?? ?? 68 1A 40 F9
  F? 43 01 D1 FE 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 13 00 40 F9 ...
  FF 43 01 D1 FE 67 01 A9 ?? ?? 06 94 ?? 7? 06 94 68 1A 40 F9 ...

Patch: MOV W0, #0 ; RET  (8 bytes — ssl_verify_ok == 0)
```

Wildcard notation: `??` = full byte wildcard, `F?` = upper nibble fixed / lower nibble wildcard.

## Config system

Config is written by the module UI via `SharedPreferences` (`MODE_PRIVATE`) and read by the hook process via `XSharedPreferences`. LSPosed service-based bridging is enabled via `<meta-data android:name="xposedsharedprefs" android:value="true"/>` in the manifest — this replaces the legacy world-readable file approach (blocked by SELinux on API 29+).

`App.onCreate()` calls `ConfigWriter.ensurePrefsFile()` to write initial defaults on first launch, guaranteeing the prefs file exists on disk before any hook process reads it via the LSPosed service.

`XposedPrefs.reload()` recreates the `XSharedPreferences` instance rather than calling `.reload()` on the existing one (stale cache bug in the old instance).

## iptables rules

Rules use `iptables -t nat OUTPUT DNAT` to redirect TCP 443/80 to the proxy.

- **Global redirect**: applies to all TCP 80/443 from the device; tracked in-memory and shown in Active Rules
- **Per-app rules**: apply UID-scoped DNAT rules on top of the global redirect
- **Flush**: `iptables -t nat -F OUTPUT` clears the entire chain

`ActiveRulesActivity` shows both global and per-app rules in a RecyclerView with per-rule delete (confirm dialog) and flush-all (confirm dialog). The live `iptables -t nat -L OUTPUT -n` dump is shown below and refreshed on demand.

**Root required** — all iptables commands run via `su -c`.

## UI

### MainActivity

- **Settings card**: logging toggle
- **Target Applications**: chip group of enabled apps; long-press chip to show package name; close icon to remove
- **Proxy redirect (iptables)**: host/port inputs scroll into view when focused (keyboard-aware via `windowSoftInputMode=adjustResize` + `OnGlobalLayoutListener`); Apply Rules / Flush Rules buttons; inline NAT dump shown after apply
- **View Active Rules**: opens `ActiveRulesActivity`

### AppListActivity

- Per-app enable switch; hook category chips: **TrustMgr**, **OkHttp**, **WebView**, **Native**
- Flutter bypass mode chips: **Native** (in-memory C++ patch) / **Kotlin** (file patch)
- Domain filter dialog per app

### ActiveRulesActivity

- RecyclerView: global redirect entry (if active) + per-app rules; each row shows label, proxy destination, uid/scope
- Per-rule delete button → confirm dialog → `removeRule()` / `removeGlobalRedirect()` on IO dispatcher
- **Flush All** button → confirm dialog → `flushAll()` → clears entire NAT chain
- Live `iptables -t nat -L OUTPUT -n` dump, horizontally scrollable
