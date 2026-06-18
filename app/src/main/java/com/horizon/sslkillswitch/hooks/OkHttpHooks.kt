package com.horizon.sslkillswitch.hooks

import com.horizon.sslkillswitch.config.HookConfig
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers

object OkHttpHooks {

    fun apply(cl: ClassLoader, pkg: String, config: HookConfig) {
        hookCertificatePinner(cl)
        hookOkHttpBuilder(cl)
        hookTrustKit(cl)
    }

    private fun hookCertificatePinner(cl: ClassLoader) {
        val noop = object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                param.result = null
            }
        }

        // OkHttp 3.x — CertificatePinner.check(String, List)
        try {
            XposedHelpers.findAndHookMethod(
                "okhttp3.CertificatePinner", cl,
                "check", String::class.java, List::class.java,
                noop
            )
        } catch (_: Throwable) {}

        // OkHttp 4.x — check$okhttp (internal Kotlin method)
        try {
            XposedHelpers.findAndHookMethod(
                "okhttp3.CertificatePinner", cl,
                "check\$okhttp", String::class.java, java.util.function.Function::class.java,
                noop
            )
        } catch (_: Throwable) {}

        // Legacy OkHttp (okhttp2)
        try {
            XposedHelpers.findAndHookMethod(
                "com.squareup.okhttp.CertificatePinner", cl,
                "check", String::class.java, java.security.cert.Certificate::class.java,
                noop
            )
        } catch (_: Throwable) {}
    }

    private fun hookOkHttpBuilder(cl: ClassLoader) {
        // Strip CertificatePinner when OkHttpClient is built
        try {
            XposedHelpers.findAndHookMethod(
                "okhttp3.OkHttpClient\$Builder", cl, "build",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        try {
                            val emptyPinner = XposedHelpers.callStaticMethod(
                                XposedHelpers.findClass("okhttp3.CertificatePinner", cl),
                                "getDEFAULT"
                            )
                            XposedHelpers.setObjectField(param.thisObject, "certificatePinner", emptyPinner)
                        } catch (_: Throwable) {}
                    }
                }
            )
        } catch (_: Throwable) {}

        // Also null out the hostnameVerifier to allow-all
        try {
            XposedHelpers.findAndHookMethod(
                "okhttp3.OkHttpClient\$Builder", cl, "build",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        try {
                            val client = param.result ?: return
                            XposedHelpers.setObjectField(
                                client, "hostnameVerifier",
                                javax.net.ssl.HostnameVerifier { _, _ -> true }
                            )
                        } catch (_: Throwable) {}
                    }
                }
            )
        } catch (_: Throwable) {}
    }

    private fun hookTrustKit(cl: ClassLoader) {
        // TrustKit OkHostnameVerifier
        try {
            XposedHelpers.findAndHookMethod(
                "com.datatheorem.android.trustkit.pinning.OkHostnameVerifier", cl,
                "verify", String::class.java, javax.net.ssl.SSLSession::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = true
                    }
                }
            )
        } catch (_: Throwable) {}

        try {
            XposedHelpers.findAndHookMethod(
                "com.datatheorem.android.trustkit.pinning.PinningTrustManager", cl,
                "checkServerTrusted",
                Array<java.security.cert.X509Certificate>::class.java, String::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = null
                    }
                }
            )
        } catch (_: Throwable) {}
    }
}
