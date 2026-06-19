package com.horizon.sslkillswitch.hooks

import android.net.http.SslError
import android.util.Log
import android.webkit.SslErrorHandler
import android.webkit.WebView
import de.robv.android.xposed.XC_MethodHook

private const val TAG = "SSLKillSwitch"

object WebViewHooks {

    fun apply(cl: ClassLoader, pkg: String) {
        if (loggingEnabled) Log.d(TAG, "[WebView] registering hooks for $pkg")
        hookWebViewClientSslError(cl, pkg)
    }

    private fun hookWebViewClientSslError(cl: ClassLoader, pkg: String) {
        if (loggingEnabled) Log.d(TAG, "[WebView] hookWebViewClientSslError")
        val proceed = object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                if (loggingEnabled) Log.i(TAG, "[$pkg] FIRED: WebViewClient.onReceivedSslError — calling handler.proceed()")
                val handler = param.args[1] as? SslErrorHandler ?: return
                handler.proceed()
                param.result = null
            }
        }

        tryHook("android.webkit.WebViewClient", cl, "onReceivedSslError",
            WebView::class.java, SslErrorHandler::class.java, SslError::class.java, proceed)
        tryHook("androidx.webkit.WebViewClientCompat", cl, "onReceivedSslError",
            WebView::class.java, SslErrorHandler::class.java, SslError::class.java, proceed)
    }
}
