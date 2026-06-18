package com.horizon.sslkillswitch.hooks

import android.webkit.SslErrorHandler
import android.webkit.WebView
import com.horizon.sslkillswitch.config.HookConfig
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedHelpers

object WebViewHooks {

    fun apply(cl: ClassLoader, pkg: String, config: HookConfig) {
        hookWebViewClientSslError(cl)
    }

    private fun hookWebViewClientSslError(cl: ClassLoader) {
        val proceed = object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                val handler = param.args[1] as? SslErrorHandler ?: return
                handler.proceed()
                param.result = null
            }
        }

        try {
            XposedHelpers.findAndHookMethod(
                "android.webkit.WebViewClient", cl,
                "onReceivedSslError",
                WebView::class.java, SslErrorHandler::class.java,
                android.net.http.SslError::class.java,
                proceed
            )
        } catch (_: Throwable) {}

        // WebViewClientCompat (AndroidX)
        try {
            XposedHelpers.findAndHookMethod(
                "androidx.webkit.WebViewClientCompat", cl,
                "onReceivedSslError",
                WebView::class.java, SslErrorHandler::class.java,
                android.net.http.SslError::class.java,
                proceed
            )
        } catch (_: Throwable) {}
    }
}
