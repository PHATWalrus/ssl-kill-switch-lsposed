package com.horizon.sslkillswitch.hooks

import com.horizon.sslkillswitch.config.HookConfig
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

object TrustManagerHooks {

    private val permissiveTrustManager = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    private val noop = object : XC_MethodHook() {
        override fun beforeHookedMethod(param: MethodHookParam) {
            param.result = null
        }
    }

    fun apply(cl: ClassLoader, pkg: String, config: HookConfig) {
        hookTrustManagerImpl(cl)
        hookHostnameVerifier(cl)
        hookSSLContextInit(cl)
        hookConscrypt(cl)
        hookNetworkSecurityTrustManager(cl)
    }

    private fun hookTrustManagerImpl(cl: ClassLoader) {
        // checkServerTrusted(X509Certificate[], String, OpenSSLSocketImpl) — 3-arg variant
        try {
            XposedHelpers.findAndHookMethod(
                "com.android.org.conscrypt.TrustManagerImpl", cl,
                "checkServerTrusted",
                Array<X509Certificate>::class.java,
                String::class.java,
                "com.android.org.conscrypt.OpenSSLSocketImpl",
                noop
            )
        } catch (_: Throwable) {}

        // checkServerTrusted(X509Certificate[], String) — 2-arg variant
        try {
            XposedHelpers.findAndHookMethod(
                "com.android.org.conscrypt.TrustManagerImpl", cl,
                "checkServerTrusted",
                Array<X509Certificate>::class.java,
                String::class.java,
                noop
            )
        } catch (_: Throwable) {}

        // checkTrustedRecursive — internal verify chain
        try {
            XposedHelpers.findAndHookMethod(
                "com.android.org.conscrypt.TrustManagerImpl", cl,
                "checkTrustedRecursive",
                X509Certificate::class.java,
                ByteArray::class.java,
                ByteArray::class.java,
                List::class.java,
                List::class.java,
                Set::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = emptyList<X509Certificate>()
                    }
                }
            )
        } catch (_: Throwable) {}

        // verifyChain — older Conscrypt
        try {
            XposedHelpers.findAndHookMethod(
                "com.android.org.conscrypt.TrustManagerImpl", cl,
                "verifyChain",
                Array<X509Certificate>::class.java,
                Array<X509Certificate>::class.java,
                String::class.java,
                Boolean::class.javaPrimitiveType,
                ByteArray::class.java,
                ByteArray::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        @Suppress("UNCHECKED_CAST")
                        param.result = param.args[0] as Array<X509Certificate>
                    }
                }
            )
        } catch (_: Throwable) {}
    }

    private fun hookHostnameVerifier(cl: ClassLoader) {
        val alwaysTrue = object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                param.result = true
            }
        }

        try {
            XposedHelpers.findAndHookMethod(
                "javax.net.ssl.HttpsURLConnection", cl,
                "setDefaultHostnameVerifier",
                javax.net.ssl.HostnameVerifier::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.args[0] = javax.net.ssl.HostnameVerifier { _, _ -> true }
                    }
                }
            )
        } catch (_: Throwable) {}

        try {
            XposedHelpers.findAndHookMethod(
                "javax.net.ssl.HttpsURLConnection", cl,
                "setHostnameVerifier",
                javax.net.ssl.HostnameVerifier::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.args[0] = javax.net.ssl.HostnameVerifier { _, _ -> true }
                    }
                }
            )
        } catch (_: Throwable) {}

        // Known HostnameVerifier implementations
        listOf(
            "com.android.org.conscrypt.OSSLHostnameVerifier",
            "javax.net.ssl.DefaultHostnameVerifier",
            "sun.security.util.HostnameChecker"
        ).forEach { className ->
            try {
                XposedHelpers.findAndHookMethod(
                    className, cl,
                    "verify",
                    String::class.java,
                    javax.net.ssl.SSLSession::class.java,
                    alwaysTrue
                )
            } catch (_: Throwable) {}
        }
    }

    private fun hookSSLContextInit(cl: ClassLoader) {
        try {
            XposedHelpers.findAndHookMethod(
                SSLContext::class.java,
                "init",
                Array<javax.net.ssl.KeyManager>::class.java,
                Array<TrustManager>::class.java,
                java.security.SecureRandom::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.args[1] = arrayOf<TrustManager>(permissiveTrustManager)
                    }
                }
            )
        } catch (e: Throwable) {
            XposedBridge.log("[SSLKillSwitch] SSLContext.init hook failed: ${e.message}")
        }
    }

    private fun hookConscrypt(cl: ClassLoader) {
        try {
            XposedHelpers.findAndHookMethod(
                "com.android.org.conscrypt.ConscryptEngine", cl,
                "verifyCertificateChain",
                Array<ByteArray>::class.java,
                String::class.java,
                noop
            )
        } catch (_: Throwable) {}

        try {
            XposedHelpers.findAndHookMethod(
                "com.android.org.conscrypt.ConscryptFileDescriptorSocket", cl,
                "verifyCertificateChain",
                Array<ByteArray>::class.java,
                String::class.java,
                noop
            )
        } catch (_: Throwable) {}
    }

    private fun hookNetworkSecurityTrustManager(cl: ClassLoader) {
        // Android 7+ pins via network_security_config
        try {
            XposedHelpers.findAndHookMethod(
                "android.security.net.config.NetworkSecurityTrustManager", cl,
                "checkPins",
                List::class.java,
                noop
            )
        } catch (_: Throwable) {}

        try {
            XposedHelpers.findAndHookMethod(
                "android.security.net.config.NetworkSecurityTrustManager", cl,
                "checkServerTrusted",
                Array<X509Certificate>::class.java,
                String::class.java,
                noop
            )
        } catch (_: Throwable) {}
    }
}
