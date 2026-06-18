# SSL Kill Switch — LSPosed Module

LSPosed module for disabling SSL certificate pinning on Android. Covers Java-layer pinning (OkHttp, TrustManager, Conscrypt, WebView) and native-layer pinning (BoringSSL embedded in Flutter, React Native, and other NDK-based apps).

## Features

- **Java SSL bypass**: X509TrustManager, HostnameVerifier, OkHttp CertificatePinner (v3/v4), TrustKit, Conscrypt, WebViewClient
- **Native SSL bypass**: BoringSSL inline hooks via ARM64 trampoline — covers Flutter (`libflutter.so`), React Native, and any app embedding BoringSSL/OpenSSL
- **Per-app scope**: enable hooks only for selected packages
- **Domain filter**: optionally restrict bypass to specific hostnames
- **iptables redirect**: configure per-UID NAT rules to forward app traffic to a proxy (Burp, mitmproxy)
- Root required only for iptables rules; SSL bypass works without root via LSPosed scope

## Architecture

```
MainHook (IXposedHookLoadPackage)
├── TrustManagerHooks   — javax.net.ssl.*, conscrypt internals
├── OkHttpHooks         — okhttp3.CertificatePinner, okhttp3.internal
├── WebViewHooks        — WebViewClient.onReceivedSslError
└── NativeHooks         — loads libssl_kill_switch.so → ARM64 inline hooks
                          targets: SSL_CTX_new, SSL_CTX_set_custom_verify,
                                   SSL_get_verify_result, X509_verify_cert
```

Config is shared via XSharedPreferences and written by the module UI (MainActivity).

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
