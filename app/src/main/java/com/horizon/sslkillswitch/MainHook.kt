package com.horizon.sslkillswitch

import android.util.Log
import com.horizon.sslkillswitch.hooks.NativeHooks
import com.horizon.sslkillswitch.hooks.OkHttpHooks
import com.horizon.sslkillswitch.hooks.TrustManagerHooks
import com.horizon.sslkillswitch.hooks.WebViewHooks
import io.github.libxposed.api.XposedModule
import io.github.libxposed.api.XposedModuleInterface

class MainHook : XposedModule() {

    override fun onPackageLoaded(param: XposedModuleInterface.PackageLoadedParam) {
        val pkg = param.packageName
        if (pkg == "com.horizon.sslkillswitch") return
        if (pkg.startsWith("android") && pkg != "android") return

        Log.d(TAG, "Hooking $pkg")

        val cl = param.defaultClassLoader

        TrustManagerHooks.apply(this, cl, pkg)
        OkHttpHooks.apply(this, cl, pkg)
        WebViewHooks.apply(this, cl, pkg)
        NativeHooks.apply(cl, pkg)
    }

    companion object {
        const val TAG = "SSLKillSwitch"
    }
}
