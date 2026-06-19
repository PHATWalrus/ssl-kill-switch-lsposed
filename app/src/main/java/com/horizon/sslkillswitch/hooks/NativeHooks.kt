package com.horizon.sslkillswitch.hooks

import android.util.Log

private const val TAG = "SSLKillSwitch"

object NativeHooks {

    private var loaded = false

    fun loadLib(pkg: String): Boolean {
        if (loaded) return true
        return try {
            System.loadLibrary("ssl_kill_switch")
            loaded = true
            if (loggingEnabled) Log.d(TAG, "[$pkg] native lib loaded")
            true
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "[$pkg] native lib load failed: ${e.message}")
            false
        }
    }

    @JvmStatic external fun nativeScanAndHook()
    @JvmStatic external fun nativePatchFlutter()

    /** Patches libflutter.so scoped to paths containing [pkg], for precise per-app targeting. */
    @JvmStatic external fun nativePatchFlutterForPkg(pkg: String)
}
