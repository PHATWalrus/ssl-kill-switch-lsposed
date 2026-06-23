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

    /**
     * Boot-classpath hooks — called from initZygote.
     * Uses ClassLoader.getSystemClassLoader() which is the boot classpath in Zygote.
     * These hooks are inherited by ALL forked app processes.
     */
    fun applySystem() {
        val cl = ClassLoader.getSystemClassLoader()
        if (loggingEnabled) Log.i(TAG, "[system] boot-classpath TrustManager hooks")
        hookTrustManagerImpl(cl, "system")
        hookTrustManagerExtensions(cl, "system")
        hookHostnameVerifier(cl, "system")
        hookSSLContextInit("system")
        hookConscrypt(cl, "system")
        hookNetworkSecurityTrustManager(cl, "system")
    }

    /** Per-process hook with app classloader — covers app-bundled conscrypt variants. */
    fun apply(cl: ClassLoader, pkg: String) {
        if (loggingEnabled) Log.d(TAG, "[TrustManager] registering hooks for $pkg")
        hookTrustManagerImpl(cl, pkg)
        hookTrustManagerExtensions(cl, pkg)
        hookHostnameVerifier(cl, pkg)
        hookSSLContextInit(pkg)
        hookConscrypt(cl, pkg)
        hookNetworkSecurityTrustManager(cl, pkg)
    }

    private fun hookTrustManagerImpl(cl: ClassLoader, pkg: String) {
        if (loggingEnabled) Log.d(TAG, "[TrustManager] hookTrustManagerImpl [$pkg]")
        val noop = object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                if (loggingEnabled) Log.i(TAG, "[$pkg] FIRED: TrustManagerImpl.${param.method.name}")
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
                    if (loggingEnabled) Log.i(TAG, "[$pkg] FIRED: TrustManagerImpl.checkTrustedRecursive")
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
                    if (loggingEnabled) Log.i(TAG, "[$pkg] FIRED: TrustManagerImpl.verifyChain")
                    @Suppress("UNCHECKED_CAST")
                    param.result = param.args[0] as Array<X509Certificate>
                }
            }
        )

        // 3-arg overload checkServerTrusted(chain, authType, String host) returns
        // List<X509Certificate> (the cleaned chain). This is the path OkHttp's
        // AndroidPlatform hits via X509TrustManagerExtensions — must return the chain, NOT null.
        tryHook("com.android.org.conscrypt.TrustManagerImpl", cl, "checkServerTrusted",
            Array<X509Certificate>::class.java, String::class.java, String::class.java,
            object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    if (loggingEnabled) Log.i(TAG, "[$pkg] FIRED: TrustManagerImpl.checkServerTrusted(host)")
                    @Suppress("UNCHECKED_CAST")
                    param.result = (param.args[0] as Array<X509Certificate>).toList()
                }
            }
        )
    }

    // android.net.http.X509TrustManagerExtensions.checkServerTrusted(chain, authType, host)
    // returns List<X509Certificate>. Used directly by AndroidPinning and many custom pinners.
    private fun hookTrustManagerExtensions(cl: ClassLoader, pkg: String) {
        if (loggingEnabled) Log.d(TAG, "[TrustManager] hookTrustManagerExtensions [$pkg]")
        tryHook("android.net.http.X509TrustManagerExtensions", cl, "checkServerTrusted",
            Array<X509Certificate>::class.java, String::class.java, String::class.java,
            object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    if (loggingEnabled) Log.i(TAG, "[$pkg] FIRED: X509TrustManagerExtensions.checkServerTrusted")
                    @Suppress("UNCHECKED_CAST")
                    param.result = (param.args[0] as Array<X509Certificate>).toList()
                }
            }
        )
    }

    private fun hookHostnameVerifier(cl: ClassLoader, pkg: String) {
        if (loggingEnabled) Log.d(TAG, "[TrustManager] hookHostnameVerifier [$pkg]")
        val alwaysTrue = object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                if (loggingEnabled) Log.i(TAG, "[$pkg] FIRED: HostnameVerifier.verify")
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

        // Catch anonymous/custom verifiers set via conn.setHostnameVerifier(...) —
        // not reachable by class name. Swap the arg for an always-true verifier.
        val permissive = javax.net.ssl.HostnameVerifier { _, _ -> true }
        val swapArg = object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                if (loggingEnabled) Log.i(TAG, "[$pkg] FIRED: HttpsURLConnection.${param.method.name} — swapping verifier")
                param.args[0] = permissive
            }
        }
        tryHook(javax.net.ssl.HttpsURLConnection::class.java, "setHostnameVerifier",
            javax.net.ssl.HostnameVerifier::class.java, swapArg)
        tryHook(javax.net.ssl.HttpsURLConnection::class.java, "setDefaultHostnameVerifier",
            javax.net.ssl.HostnameVerifier::class.java, swapArg)
    }

    private fun hookSSLContextInit(pkg: String) {
        if (loggingEnabled) Log.d(TAG, "[TrustManager] hookSSLContextInit [$pkg]")
        tryHook(SSLContext::class.java, "init",
            Array<javax.net.ssl.KeyManager>::class.java,
            Array<TrustManager>::class.java,
            java.security.SecureRandom::class.java,
            object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    if (loggingEnabled) Log.i(TAG, "[$pkg] FIRED: SSLContext.init — replacing TrustManagers")
                    param.args[1] = arrayOf<TrustManager>(permissiveTrustManager)
                }
            }
        )
    }

    private fun hookConscrypt(cl: ClassLoader, pkg: String) {
        if (loggingEnabled) Log.d(TAG, "[TrustManager] hookConscrypt [$pkg]")
        val noop = object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                if (loggingEnabled) Log.i(TAG, "[$pkg] FIRED: Conscrypt.${param.method.name}")
                param.result = null
            }
        }
        val params = arrayOf<Any>(Array<ByteArray>::class.java, String::class.java, noop)

        tryHook("com.android.org.conscrypt.ConscryptEngine", cl, "verifyCertificateChain", *params)
        tryHook("com.android.org.conscrypt.ConscryptFileDescriptorSocket", cl, "verifyCertificateChain", *params)
    }

    private fun hookNetworkSecurityTrustManager(cl: ClassLoader, pkg: String) {
        if (loggingEnabled) Log.d(TAG, "[TrustManager] hookNetworkSecurityTrustManager [$pkg]")
        val noop = object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                if (loggingEnabled) Log.i(TAG, "[$pkg] FIRED: NetworkSecurityTrustManager.${param.method.name}")
                param.result = null
            }
        }

        tryHook("android.security.net.config.NetworkSecurityTrustManager", cl,
            "checkPins", List::class.java, noop)
        tryHook("android.security.net.config.NetworkSecurityTrustManager", cl,
            "checkServerTrusted", Array<X509Certificate>::class.java, String::class.java, noop)
    }
}
