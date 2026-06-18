package com.horizon.sslkillswitch.hooks

import de.robv.android.xposed.XposedBridge

object NativeHooks {

    private var loaded = false

    fun apply(cl: ClassLoader, pkg: String) {
        if (loaded) {
            // Library already in process — re-run hook scan for this package
            nativeScanAndHook()
            return
        }
        try {
            System.loadLibrary("ssl_kill_switch")
            loaded = true
            XposedBridge.log("[SSLKillSwitch] Native library loaded for $pkg")
            nativeScanAndHook()
        } catch (e: UnsatisfiedLinkError) {
            XposedBridge.log("[SSLKillSwitch] Native library load failed: ${e.message}")
        }
    }

    @JvmStatic
    external fun nativeScanAndHook()
}
