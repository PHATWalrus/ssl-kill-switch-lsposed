package com.horizon.sslkillswitch

import android.util.Log
import com.horizon.sslkillswitch.hooks.NativeHooks
import com.horizon.sslkillswitch.hooks.OkHttpHooks
import com.horizon.sslkillswitch.hooks.TrustManagerHooks
import com.horizon.sslkillswitch.hooks.WebViewHooks
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam

internal const val TAG = "SSLKillSwitch"

class MainHook : IXposedHookLoadPackage {

    override fun handleLoadPackage(lpparam: LoadPackageParam) {
        val pkg = lpparam.packageName
        if (pkg == "com.horizon.sslkillswitch") return

        Log.i(TAG, "--- MODULE ALIVE: $pkg ---")

        try {
            val cl = lpparam.classLoader
            TrustManagerHooks.apply(cl, pkg)
            OkHttpHooks.apply(cl, pkg)
            WebViewHooks.apply(cl, pkg)
            NativeHooks.apply(cl, pkg)
        } catch (t: Throwable) {
            Log.e(TAG, "hook failed pkg=$pkg", t)
        }
    }
}
