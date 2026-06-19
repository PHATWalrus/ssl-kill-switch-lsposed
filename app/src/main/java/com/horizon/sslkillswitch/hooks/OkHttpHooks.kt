package com.horizon.sslkillswitch.hooks

import android.util.Log
import de.robv.android.xposed.XC_MethodHook
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLSession

private const val TAG = "SSLKillSwitch"

object OkHttpHooks {

    fun apply(cl: ClassLoader, pkg: String) {
        if (loggingEnabled) Log.d(TAG, "[OkHttp] registering hooks for $pkg")
        hookCertificatePinner(cl, pkg)
        hookOkHttpClientBuild(cl, pkg)
        hookTrustKit(cl, pkg)
    }

    private fun hookCertificatePinner(cl: ClassLoader, pkg: String) {
        if (loggingEnabled) Log.d(TAG, "[OkHttp] hookCertificatePinner")
        val noop = object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                if (loggingEnabled) Log.i(TAG, "[$pkg] FIRED: CertificatePinner.${param.method.name}")
                param.result = null
            }
        }

        tryHook("okhttp3.CertificatePinner", cl, "check",
            String::class.java, List::class.java, noop)
        tryHook("okhttp3.CertificatePinner", cl, "check\$okhttp",
            String::class.java, java.util.function.Function::class.java, noop)
        tryHook("com.squareup.okhttp.CertificatePinner", cl, "check",
            String::class.java, Certificate::class.java, noop)
    }

    private fun hookOkHttpClientBuild(cl: ClassLoader, pkg: String) {
        if (loggingEnabled) Log.d(TAG, "[OkHttp] hookOkHttpClientBuild")
        tryHook("okhttp3.OkHttpClient\$Builder", cl, "build",
            object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    val client = param.result ?: return
                    if (loggingEnabled) Log.i(TAG, "[$pkg] FIRED: OkHttpClient.Builder.build — replacing hostnameVerifier")
                    setField(client, "hostnameVerifier", HostnameVerifier { _: String, _: SSLSession -> true })
                }
            }
        )
    }

    private fun hookTrustKit(cl: ClassLoader, pkg: String) {
        if (loggingEnabled) Log.d(TAG, "[OkHttp] hookTrustKit")
        tryHook("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier", cl, "verify",
            String::class.java, SSLSession::class.java,
            object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    if (loggingEnabled) Log.i(TAG, "[$pkg] FIRED: TrustKit OkHostnameVerifier.verify")
                    param.result = true
                }
            }
        )
        tryHook("com.datatheorem.android.trustkit.pinning.PinningTrustManager", cl, "checkServerTrusted",
            Array<X509Certificate>::class.java, String::class.java,
            object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    if (loggingEnabled) Log.i(TAG, "[$pkg] FIRED: TrustKit PinningTrustManager.checkServerTrusted")
                    param.result = null
                }
            }
        )
    }
}
