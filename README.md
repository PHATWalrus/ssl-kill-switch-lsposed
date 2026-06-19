# SSL Kill Switch — LSPosed Module

LSPosed module for disabling SSL certificate pinning on Android. Covers Java-layer pinning (OkHttp, TrustManager, Conscrypt, WebView) and native-layer pinning (BoringSSL embedded in Flutter, React Native, and other NDK-based apps).

## Features

- **Java SSL bypass**: X509TrustManager, HostnameVerifier, OkHttp CertificatePinner (v3/v4), TrustKit, Conscrypt, WebViewClient
- **Native SSL bypass**: BoringSSL inline hooks via ARM64 trampoline — covers Flutter (`libflutter.so`), React Native, and any app embedding BoringSSL/OpenSSL
- **Per-app scope**: enable hooks only for selected packages
- **Per-hook toggle**: enable/disable TrustManager, OkHttp, WebView, Native hooks independently per app; chips show green (active) or red (inactive)
- **Domain filter**: optionally restrict bypass to specific hostnames
- **iptables redirect**: configure per-UID NAT rules to forward app traffic to a proxy (Burp, mitmproxy)
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
└── IXposedHookLoadPackage.handleLoadPackage() — fires per-process, ALL packages, no filter
    ├── TrustManagerHooks.apply(cl, pkg)     — re-applies with app classloader
    ├── OkHttpHooks.apply(cl, pkg)           — only if okhttp3.OkHttpClient exists in classloader
    ├── WebViewHooks.apply(cl, pkg)          — WebViewClient.onReceivedSslError → handler.proceed()
    └── NativeHooks                          — loads libssl_kill_switch.so per-process
        ├── nativeScanAndHook()              — BoringSSL symbol hooks (libssl/libcrypto/librnssl)
        └── System.loadLibrary("flutter")    — hook trigger → nativePatchFlutterForPkg(pkg)
```

**Two-tier approach:**

| Tier | Scope | Mechanism | Requires selection? |
|------|-------|-----------|---------------------|
| Java SSL | All processes | Zygote boot-classpath + per-app classloader re-apply | No |
| Native SSL | Selected apps only | `ssl_kill_switch.so` load + inline trampoline patching | Yes (UI) |

Native hooks are restricted to explicitly selected apps because `nativeScanAndHook()` patches native code pages in the target process memory. Applying this globally causes `UnsatisfiedLinkError` and crashes in apps with conflicting or statically-linked native libraries (sensor SDKs, telemetry SDKs, etc.).

Config (logging toggle, proxy settings, app selection) is read via XSharedPreferences. Java hook application does not depend on prefs; native hook application requires the app to be in the enabled list with the Native category checked.

## Hook coverage

| Layer | Target | Method |
|-------|--------|--------|
| Java | `X509TrustManager.checkServerTrusted` | XposedBridge hook → no-op |
| Java | `X509TrustManager.checkClientTrusted` | hook → no-op |
| Java | `HostnameVerifier.verify` | hook → return true |
| Java | `OkHttpClient.Builder.build` | hook → strip CertificatePinner |
| Java | `CertificatePinner.check` / `check$okhttp` | hook → no-op |
| Java | `TrustManagerImpl.verifyChain` | hook → return input chain |
| Java | `SSLContext.init` | hook → inject permissive TrustManager |
| Java | `WebViewClient.onReceivedSslError` | hook → handler.proceed() |
| Native | `SSL_CTX_new` | inline hook → set SSL_VERIFY_NONE |
| Native | `SSL_CTX_set_custom_verify` | inline hook → replace callback |
| Native | `SSL_get_verify_result` | inline hook → return X509_V_OK |
| Native | `X509_verify_cert` | inline hook → return 1 |
| Native | `ssl_verify_peer_cert` (Flutter) | pattern-scan + MOV W0,#0 ; RET patch, scoped to pkg path |

## UI

### MainActivity

- **Settings card**: logging toggle (writes `KEY_LOGGING_ENABLED` to SharedPreferences; MainHook reads it at hook time)
- **Target Applications**: chip group of selected apps, long-press to show package name
- **Proxy redirect (iptables)**: host/port input, Apply Rules / Flush Rules buttons; active NAT table dump shown inline after apply or flush

### AppListActivity

- Filter chips per app: **TrustMgr**, **OkHttp**, **WebView**, **Native**
- Chip background: **green** = hook enabled, **red** = hook disabled
- Chip stroke follows the same green/red state for clear visual contrast

### ActiveRulesActivity

- **Per-app rules (session)**: in-memory list of rules applied this session (pkg, uid, proxy destination)
- **iptables -t nat -L OUTPUT -n**: live dump auto-loaded on open/resume, horizontally scrollable for long rule lines; Refresh button to reload manually

## Flutter native bypass detail

`libflutter.so` statically links BoringSSL — no exported symbols, `dlsym` always fails. Pattern-scan scans the r-x pages of `libflutter.so` for the `ssl_verify_peer_cert` function prologue and patches it to return 0 unconditionally.

The scan is triggered by hooking `System.loadLibrary("flutter")` in the target process, which fires when Flutter initializes. The JNI call `nativePatchFlutterForPkg(pkg)` passes the package name to C++ so the `/proc/self/maps` search is filtered to paths containing the package name — preventing false matches in shared-zygote scenarios where multiple app paths may appear.

```
Patterns (ARM64):
  F? 0F 1C F8 F? 5? 01 A9 ...
  F? 43 01 D1 FE 67 01 A9 ...
  FF 43 01 D1 FE 67 01 A9 ...

Patch: MOV W0, #0 ; RET  (ssl_verify_ok == 0)
```

## iptables rules

Rules use `iptables -t nat OUTPUT DNAT` to redirect TCP 443/80 to the proxy. Per-app UID scoping is applied on top of a global redirect. Flush uses `iptables -t nat -F OUTPUT`.

**Root required** — rules are executed via `su -c`.
