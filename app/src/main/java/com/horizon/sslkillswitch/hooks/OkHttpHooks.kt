package com.horizon.sslkillswitch.hooks

import android.util.Log
import com.horizon.sslkillswitch.MainHook.Companion.TAG
import io.github.libxposed.api.XposedInterface
import javax.net.ssl.HostnameVerifier

object OkHttpHooks {

    fun apply(xposed: XposedInterface, cl: ClassLoader, pkg: String) {
        hookCertificatePinner(xposed, cl, pkg)
        hookOkHttpClientBuild(xposed, cl, pkg)
        hookTrustKit(xposed, cl, pkg)
    }

    private fun hookCertificatePinner(xposed: XposedInterface, cl: ClassLoader, pkg: String) {
        val noop = XposedInterface.Hooker { chain ->
            Log.d(TAG, "[$pkg] CertificatePinner.check intercepted")
            null
        }

        // OkHttp 3.x
        tryHook(xposed, "okhttp3.CertificatePinner", cl, "check",
            arrayOf(String::class.java, List::class.java), noop)

        // OkHttp 4.x internal Kotlin method
        tryHook(xposed, "okhttp3.CertificatePinner", cl, "check\$okhttp",
            arrayOf(String::class.java, java.util.function.Function::class.java), noop)

        // Legacy okhttp2
        tryHook(xposed, "com.squareup.okhttp.CertificatePinner", cl, "check",
            arrayOf(String::class.java, java.security.cert.Certificate::class.java), noop)
    }

    private fun hookOkHttpClientBuild(xposed: XposedInterface, cl: ClassLoader, pkg: String) {
        tryHook(xposed, "okhttp3.OkHttpClient\$Builder", cl, "build", emptyArray(),
            XposedInterface.Hooker { chain ->
                val client = chain.proceed()
                if (client != null) {
                    setField(client, "hostnameVerifier", HostnameVerifier { _, _ -> true })
                    Log.d(TAG, "[$pkg] OkHttpClient.build intercepted — hostnameVerifier replaced")
                }
                client
            }
        )
    }

    private fun hookTrustKit(xposed: XposedInterface, cl: ClassLoader, pkg: String) {
        tryHook(xposed,
            "com.datatheorem.android.trustkit.pinning.OkHostnameVerifier", cl,
            "verify", arrayOf(String::class.java, javax.net.ssl.SSLSession::class.java),
            XposedInterface.Hooker { chain ->
                Log.d(TAG, "[$pkg] TrustKit OkHostnameVerifier.verify intercepted")
                true
            }
        )

        tryHook(xposed,
            "com.datatheorem.android.trustkit.pinning.PinningTrustManager", cl,
            "checkServerTrusted",
            arrayOf(Array<java.security.cert.X509Certificate>::class.java, String::class.java),
            XposedInterface.Hooker { chain ->
                Log.d(TAG, "[$pkg] TrustKit PinningTrustManager.checkServerTrusted intercepted")
                null
            }
        )
    }
}
