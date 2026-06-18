package com.horizon.sslkillswitch

import com.horizon.sslkillswitch.config.HookConfig
import com.horizon.sslkillswitch.hooks.NativeHooks
import com.horizon.sslkillswitch.hooks.OkHttpHooks
import com.horizon.sslkillswitch.hooks.TrustManagerHooks
import com.horizon.sslkillswitch.hooks.WebViewHooks
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.callbacks.XC_LoadPackage

class MainHook : IXposedHookLoadPackage {

    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        val pkg = lpparam.packageName

        // Skip system packages and ourselves
        if (pkg == "com.horizon.sslkillswitch") return
        if (pkg.startsWith("android") && pkg != "android") return

        val config = HookConfig.get("com.horizon.sslkillswitch")
        if (!config.isAppEnabled(pkg)) return

        XposedBridge.log("[SSLKillSwitch] Hooking $pkg")

        val cl = lpparam.classLoader

        TrustManagerHooks.apply(cl, pkg, config)
        OkHttpHooks.apply(cl, pkg, config)
        WebViewHooks.apply(cl, pkg, config)

        if (config.isNativeHooksEnabled()) {
            NativeHooks.apply(cl, pkg)
        }
    }
}
