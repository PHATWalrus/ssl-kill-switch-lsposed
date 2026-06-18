package com.horizon.sslkillswitch.hooks

import android.net.http.SslError
import android.util.Log
import android.webkit.SslErrorHandler
import android.webkit.WebView
import com.horizon.sslkillswitch.MainHook.Companion.TAG
import io.github.libxposed.api.XposedInterface

object WebViewHooks {

    fun apply(xposed: XposedInterface, cl: ClassLoader, pkg: String) {
        hookWebViewClientSslError(xposed, cl, pkg)
    }

    private fun hookWebViewClientSslError(xposed: XposedInterface, cl: ClassLoader, pkg: String) {
        val proceed = XposedInterface.Hooker { chain ->
            Log.d(TAG, "[$pkg] WebViewClient.onReceivedSslError intercepted — proceeding")
            val handler = chain.getArg(1) as? SslErrorHandler
            if (handler != null) {
                handler.proceed()
                null
            } else {
                chain.proceed()
            }
        }
        val paramTypes = arrayOf(WebView::class.java, SslErrorHandler::class.java, SslError::class.java)

        tryHook(xposed, "android.webkit.WebViewClient", cl, "onReceivedSslError", paramTypes, proceed)
        tryHook(xposed, "androidx.webkit.WebViewClientCompat", cl, "onReceivedSslError", paramTypes, proceed)
    }
}
