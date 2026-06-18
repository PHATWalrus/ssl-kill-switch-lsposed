package com.horizon.sslkillswitch.hooks

import android.util.Log
import com.horizon.sslkillswitch.MainHook.Companion.TAG
import io.github.libxposed.api.XposedInterface
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

    fun apply(xposed: XposedInterface, cl: ClassLoader, pkg: String) {
        hookTrustManagerImpl(xposed, cl, pkg)
        hookHostnameVerifier(xposed, cl, pkg)
        hookSSLContextInit(xposed, pkg)
        hookConscrypt(xposed, cl, pkg)
        hookNetworkSecurityTrustManager(xposed, cl, pkg)
    }

    private fun hookTrustManagerImpl(xposed: XposedInterface, cl: ClassLoader, pkg: String) {
        val noop = XposedInterface.Hooker { chain ->
            Log.d(TAG, "[$pkg] TrustManagerImpl.checkServerTrusted intercepted")
            null
        }

        tryHook(xposed, "com.android.org.conscrypt.TrustManagerImpl", cl,
            "checkServerTrusted",
            arrayOf(Array<X509Certificate>::class.java, String::class.java,
                "com.android.org.conscrypt.OpenSSLSocketImpl".let { try { cl.loadClass(it) } catch (_: Throwable) { return } }),
            noop)

        tryHook(xposed, "com.android.org.conscrypt.TrustManagerImpl", cl,
            "checkServerTrusted",
            arrayOf(Array<X509Certificate>::class.java, String::class.java),
            noop)

        tryHook(xposed, "com.android.org.conscrypt.TrustManagerImpl", cl,
            "checkTrustedRecursive",
            arrayOf(X509Certificate::class.java, ByteArray::class.java, ByteArray::class.java,
                List::class.java, List::class.java, Set::class.java),
            XposedInterface.Hooker { chain ->
                Log.d(TAG, "[$pkg] TrustManagerImpl.checkTrustedRecursive intercepted")
                emptyList<X509Certificate>()
            }
        )

        tryHook(xposed, "com.android.org.conscrypt.TrustManagerImpl", cl,
            "verifyChain",
            arrayOf(Array<X509Certificate>::class.java, Array<X509Certificate>::class.java,
                String::class.java, Boolean::class.javaPrimitiveType!!, ByteArray::class.java,
                ByteArray::class.java),
            XposedInterface.Hooker { chain ->
                Log.d(TAG, "[$pkg] TrustManagerImpl.verifyChain intercepted")
                @Suppress("UNCHECKED_CAST")
                chain.getArg(0) as Array<X509Certificate>
            }
        )
    }

    private fun hookHostnameVerifier(xposed: XposedInterface, cl: ClassLoader, pkg: String) {
        val alwaysTrue = XposedInterface.Hooker { chain ->
            Log.d(TAG, "[$pkg] HostnameVerifier.verify intercepted")
            true
        }

        listOf(
            "com.android.org.conscrypt.OSSLHostnameVerifier",
            "javax.net.ssl.DefaultHostnameVerifier",
            "sun.security.util.HostnameChecker"
        ).forEach { className ->
            tryHook(xposed, className, cl, "verify",
                arrayOf(String::class.java, javax.net.ssl.SSLSession::class.java), alwaysTrue)
        }
    }

    private fun hookSSLContextInit(xposed: XposedInterface, pkg: String) {
        tryHook(xposed, SSLContext::class.java, "init",
            arrayOf(Array<javax.net.ssl.KeyManager>::class.java,
                Array<TrustManager>::class.java, java.security.SecureRandom::class.java),
            XposedInterface.Hooker { chain ->
                Log.d(TAG, "[$pkg] SSLContext.init intercepted — replacing TrustManagers")
                val newArgs = arrayOf(chain.getArg(0), arrayOf<TrustManager>(permissiveTrustManager), chain.getArg(2))
                chain.proceed(newArgs)
            }
        )
    }

    private fun hookConscrypt(xposed: XposedInterface, cl: ClassLoader, pkg: String) {
        val noop = XposedInterface.Hooker { chain ->
            Log.d(TAG, "[$pkg] Conscrypt.verifyCertificateChain intercepted")
            null
        }
        val paramTypes: Array<Class<*>> = arrayOf(Array<ByteArray>::class.java, String::class.java)

        tryHook(xposed, "com.android.org.conscrypt.ConscryptEngine", cl,
            "verifyCertificateChain", paramTypes, noop)
        tryHook(xposed, "com.android.org.conscrypt.ConscryptFileDescriptorSocket", cl,
            "verifyCertificateChain", paramTypes, noop)
    }

    private fun hookNetworkSecurityTrustManager(xposed: XposedInterface, cl: ClassLoader, pkg: String) {
        val noop = XposedInterface.Hooker { chain ->
            Log.d(TAG, "[$pkg] NetworkSecurityTrustManager intercepted")
            null
        }

        tryHook(xposed, "android.security.net.config.NetworkSecurityTrustManager", cl,
            "checkPins", arrayOf(List::class.java), noop)
        tryHook(xposed, "android.security.net.config.NetworkSecurityTrustManager", cl,
            "checkServerTrusted",
            arrayOf(Array<X509Certificate>::class.java, String::class.java), noop)
    }
}
