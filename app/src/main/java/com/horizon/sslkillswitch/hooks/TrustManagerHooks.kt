package com.horizon.sslkillswitch.hooks

import android.util.Log
import de.robv.android.xposed.XC_MethodHook
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

private const val TAG = "SSLKillSwitch"

object TrustManagerHooks {

    private val permissiveTrustManager = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    fun apply(cl: ClassLoader, pkg: String) {
        Log.d(TAG, "[TrustManager] registering hooks for $pkg")
        hookTrustManagerImpl(cl, pkg)
        hookHostnameVerifier(cl, pkg)
        hookSSLContextInit(pkg)
        hookConscrypt(cl, pkg)
        hookNetworkSecurityTrustManager(cl, pkg)
    }

    private fun hookTrustManagerImpl(cl: ClassLoader, pkg: String) {
        Log.d(TAG, "[TrustManager] hookTrustManagerImpl")
        val noop = object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                Log.i(TAG, "[$pkg] FIRED: TrustManagerImpl.${param.method.name} — bypassed")
                param.result = null
            }
        }

        val openSSLSocketClass = try {
            cl.loadClass("com.android.org.conscrypt.OpenSSLSocketImpl")
        } catch (_: Throwable) { null }

        if (openSSLSocketClass != null) {
            tryHook("com.android.org.conscrypt.TrustManagerImpl", cl, "checkServerTrusted",
                Array<X509Certificate>::class.java, String::class.java, openSSLSocketClass, noop)
        }

        tryHook("com.android.org.conscrypt.TrustManagerImpl", cl, "checkServerTrusted",
            Array<X509Certificate>::class.java, String::class.java, noop)

        tryHook("com.android.org.conscrypt.TrustManagerImpl", cl, "checkTrustedRecursive",
            X509Certificate::class.java, ByteArray::class.java, ByteArray::class.java,
            List::class.java, List::class.java, Set::class.java,
            object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    Log.i(TAG, "[$pkg] FIRED: TrustManagerImpl.checkTrustedRecursive — bypassed")
                    param.result = emptyList<X509Certificate>()
                }
            }
        )

        tryHook("com.android.org.conscrypt.TrustManagerImpl", cl, "verifyChain",
            Array<X509Certificate>::class.java, Array<X509Certificate>::class.java,
            String::class.java, Boolean::class.javaPrimitiveType!!, ByteArray::class.java,
            ByteArray::class.java,
            object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    Log.i(TAG, "[$pkg] FIRED: TrustManagerImpl.verifyChain — bypassed")
                    @Suppress("UNCHECKED_CAST")
                    param.result = param.args[0] as Array<X509Certificate>
                }
            }
        )
    }

    private fun hookHostnameVerifier(cl: ClassLoader, pkg: String) {
        Log.d(TAG, "[TrustManager] hookHostnameVerifier")
        val alwaysTrue = object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                Log.i(TAG, "[$pkg] FIRED: HostnameVerifier.verify — returned true")
                param.result = true
            }
        }

        listOf(
            "com.android.org.conscrypt.OSSLHostnameVerifier",
            "javax.net.ssl.DefaultHostnameVerifier",
            "sun.security.util.HostnameChecker"
        ).forEach { className ->
            tryHook(className, cl, "verify",
                String::class.java, javax.net.ssl.SSLSession::class.java, alwaysTrue)
        }
    }

    private fun hookSSLContextInit(pkg: String) {
        Log.d(TAG, "[TrustManager] hookSSLContextInit")
        tryHook(SSLContext::class.java, "init",
            Array<javax.net.ssl.KeyManager>::class.java,
            Array<TrustManager>::class.java,
            java.security.SecureRandom::class.java,
            object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    Log.i(TAG, "[$pkg] FIRED: SSLContext.init — replacing TrustManagers")
                    param.args[1] = arrayOf<TrustManager>(permissiveTrustManager)
                }
            }
        )
    }

    private fun hookConscrypt(cl: ClassLoader, pkg: String) {
        Log.d(TAG, "[TrustManager] hookConscrypt")
        val noop = object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                Log.i(TAG, "[$pkg] FIRED: Conscrypt.${param.method.name} — bypassed")
                param.result = null
            }
        }
        val params = arrayOf<Any>(Array<ByteArray>::class.java, String::class.java, noop)

        tryHook("com.android.org.conscrypt.ConscryptEngine", cl, "verifyCertificateChain", *params)
        tryHook("com.android.org.conscrypt.ConscryptFileDescriptorSocket", cl, "verifyCertificateChain", *params)
    }

    private fun hookNetworkSecurityTrustManager(cl: ClassLoader, pkg: String) {
        Log.d(TAG, "[TrustManager] hookNetworkSecurityTrustManager")
        val noop = object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                Log.i(TAG, "[$pkg] FIRED: NetworkSecurityTrustManager.${param.method.name} — bypassed")
                param.result = null
            }
        }

        tryHook("android.security.net.config.NetworkSecurityTrustManager", cl,
            "checkPins", List::class.java, noop)
        tryHook("android.security.net.config.NetworkSecurityTrustManager", cl,
            "checkServerTrusted", Array<X509Certificate>::class.java, String::class.java, noop)
    }
}
