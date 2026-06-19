package com.horizon.sslkillswitch.hooks

import android.util.Log
private const val TAG = "SSLKillSwitch"

object NativeHooks {

    private var loaded = false

    fun apply(cl: ClassLoader, pkg: String) {
        if (loaded) {
            nativeScanAndHook()
            return
        }
        try {
            System.loadLibrary("ssl_kill_switch")
            loaded = true
            Log.d(TAG, "[$pkg] native library loaded")
            nativeScanAndHook()
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "[$pkg] native library load failed: ${e.message}")
        }
    }

    @JvmStatic
    external fun nativeScanAndHook()
}
