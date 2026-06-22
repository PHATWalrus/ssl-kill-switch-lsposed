package com.horizon.sslkillswitch.hooks

import android.net.http.SslError
import android.util.Log
import android.webkit.SslErrorHandler
import android.webkit.WebView
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge

private const val TAG = "SSLKillSwitch"

object WebViewHooks {

    // Install cancel hook once per process — hookMethod on system class is global
    @Volatile private var cancelHookInstalled = false

    fun apply(cl: ClassLoader, pkg: String) {
        if (loggingEnabled) Log.d(TAG, "[WebView] registering hooks for $pkg")
        hookStandardWebViewClient(cl, pkg)
        hookSslErrorHandlerCancel(pkg)
        hookCordova(cl, pkg)
        hookX5(cl, pkg)
    }

    // Try multiple method names — covers non-standard handler APIs in custom WebView SDKs
    private fun smartProceed(handler: Any?, pkg: String) {
        if (handler == null) return
        for (name in listOf("proceed", "continueLoad", "continue", "ignore")) {
            runCatching {
                handler.javaClass.getMethod(name).invoke(handler)
                if (loggingEnabled) Log.i(TAG, "[$pkg] handler.$name() OK (${handler.javaClass.simpleName})")
                return
            }
        }
        Log.w(TAG, "[$pkg] no proceed-like method on ${handler.javaClass.name}")
    }

    private fun sslProceed(pkg: String) = object : XC_MethodHook() {
        override fun beforeHookedMethod(param: MethodHookParam) {
            if (loggingEnabled) Log.i(TAG, "[$pkg] onReceivedSslError — proceeding")
            smartProceed(param.args.getOrNull(1), pkg)
            param.result = null
        }
    }

    private fun skip(pkg: String) = object : XC_MethodHook() {
        override fun beforeHookedMethod(param: MethodHookParam) {
            if (loggingEnabled) Log.i(TAG, "[$pkg] onReceivedError — suppressed")
            param.result = null
        }
    }

    private fun hookStandardWebViewClient(cl: ClassLoader, pkg: String) {
        val proceed = sslProceed(pkg)
        val noError = skip(pkg)

        tryHook("android.webkit.WebViewClient", cl, "onReceivedSslError",
            WebView::class.java, SslErrorHandler::class.java, SslError::class.java, proceed)
        tryHook("androidx.webkit.WebViewClientCompat", cl, "onReceivedSslError",
            WebView::class.java, SslErrorHandler::class.java, SslError::class.java, proceed)

        // Suppress both onReceivedError variants so TLS errors don't surface as page errors
        tryHook("android.webkit.WebViewClient", cl, "onReceivedError",
            "android.webkit.WebView", "int", "java.lang.String", "java.lang.String", noError)
        tryHook("android.webkit.WebViewClient", cl, "onReceivedError",
            "android.webkit.WebView", "android.webkit.WebResourceRequest",
            "android.webkit.WebResourceError", noError)
    }

    // Redirect SslErrorHandler.cancel() → proceed() — catches subclass overrides that call
    // handler.cancel() directly (or do nothing, letting the default cancel fire).
    // This is global per-process, so install once.
    private fun hookSslErrorHandlerCancel(pkg: String) {
        if (cancelHookInstalled) return
        cancelHookInstalled = true
        runCatching {
            val cls = SslErrorHandler::class.java
            val proceed = cls.getMethod("proceed")
            XposedBridge.hookMethod(cls.getMethod("cancel"), object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    if (loggingEnabled) Log.i(TAG, "[$pkg] SslErrorHandler.cancel() → proceed()")
                    runCatching { proceed.invoke(param.thisObject) }
                    param.result = null
                }
            })
            if (loggingEnabled) Log.d(TAG, "  [OK] SslErrorHandler.cancel → proceed")
        }.onFailure { Log.e(TAG, "  [FAIL] SslErrorHandler.cancel hook: ${it.message}") }
    }

    private fun hookCordova(cl: ClassLoader, pkg: String) {
        val proceed = sslProceed(pkg)
        tryHook("org.apache.cordova.CordovaWebViewClient", cl, "onReceivedSslError",
            "android.webkit.WebView", "android.webkit.SslErrorHandler",
            "android.net.http.SslError", proceed)
        tryHook("org.apache.cordova.engine.SystemWebViewClient", cl, "onReceivedSslError",
            "android.webkit.WebView", "android.webkit.SslErrorHandler",
            "android.net.http.SslError", proceed)
    }

    private fun hookX5(cl: ClassLoader, pkg: String) {
        val proceed = sslProceed(pkg)
        val noError = skip(pkg)

        // X5 WebViewClient with native X5 param types
        tryHook("com.tencent.smtt.sdk.WebViewClient", cl, "onReceivedSslError",
            "com.tencent.smtt.sdk.WebView",
            "com.tencent.smtt.export.external.interfaces.SslErrorHandler",
            "com.tencent.smtt.export.external.interfaces.SslError", proceed)

        // SystemWebViewClient — X5 wrapper around standard Android WebView, uses Android types
        tryHook("com.tencent.smtt.sdk.SystemWebViewClient", cl, "onReceivedSslError",
            "android.webkit.WebView", "android.webkit.SslErrorHandler",
            "android.net.http.SslError", proceed)
        tryHook("com.tencent.smtt.sdk.SystemWebViewClient", cl, "onReceivedError",
            "android.webkit.WebView", "int", "java.lang.String", "java.lang.String", noError)
        tryHook("com.tencent.smtt.sdk.SystemWebViewClient", cl, "onReceivedError",
            "android.webkit.WebView", "android.webkit.WebResourceRequest",
            "android.webkit.WebResourceError", noError)
    }
}
