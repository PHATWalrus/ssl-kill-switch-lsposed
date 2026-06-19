package com.horizon.sslkillswitch

import android.util.Log
import com.horizon.sslkillswitch.config.KEY_ENABLED_APPS
import com.horizon.sslkillswitch.config.KEY_HOOK_NATIVE
import com.horizon.sslkillswitch.config.KEY_LOGGING_ENABLED
import com.horizon.sslkillswitch.config.PREFS_NAME
import com.horizon.sslkillswitch.hooks.NativeHooks
import com.horizon.sslkillswitch.hooks.OkHttpHooks
import com.horizon.sslkillswitch.hooks.TrustManagerHooks
import com.horizon.sslkillswitch.hooks.WebViewHooks
import com.horizon.sslkillswitch.hooks.loggingEnabled
import com.horizon.sslkillswitch.hooks.tryHook
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.IXposedHookZygoteInit
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XSharedPreferences
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam

internal const val TAG = "SSLKillSwitch"

class MainHook : IXposedHookLoadPackage, IXposedHookZygoteInit {

    private val prefs by lazy { XSharedPreferences("com.horizon.sslkillswitch", PREFS_NAME) }

    override fun initZygote(startupParam: IXposedHookZygoteInit.StartupParam) {
        Log.i(TAG, "initZygote — system-level SSL hooks to boot classpath")
        TrustManagerHooks.applySystem()
    }

    override fun handleLoadPackage(lpparam: LoadPackageParam) {
        val pkg = lpparam.packageName
        if (pkg == "com.horizon.sslkillswitch") return

        runCatching { prefs.reload() }
        loggingEnabled = prefs.getBoolean(KEY_LOGGING_ENABLED, true)

        if (loggingEnabled) Log.i(TAG, "handleLoadPackage: $pkg")

        val cl = lpparam.classLoader

        // ── 1. Java SSL hooks — ALL packages ─────────────────────────────────
        try {
            TrustManagerHooks.apply(cl, pkg)
        } catch (t: Throwable) {
            Log.e(TAG, "TM hook failed pkg=$pkg", t)
        }

        try {
            cl.loadClass("okhttp3.OkHttpClient")
            OkHttpHooks.apply(cl, pkg)
        } catch (_: ClassNotFoundException) { }
        catch (t: Throwable) { Log.e(TAG, "OkHttp hook failed pkg=$pkg", t) }

        try {
            WebViewHooks.apply(cl, pkg)
        } catch (t: Throwable) {
            Log.e(TAG, "WebView hook failed pkg=$pkg", t)
        }

        // ── 2. Native hooks + System.loadLibrary — selected apps only ────────────
        // System.loadLibrary is @CallerSensitive. LSPosed invokes the original via
        // Method.invoke (reflection) which breaks caller-sensitivity and causes the
        // wrong ClassLoader to be used for library path resolution. Hooking it for
        // ALL packages makes unrelated native libs (e.g. libfilterengine.so) fail
        // with "not found" because the caller class is lost. Keep this hook scoped
        // to explicitly selected apps only.
        val enabledApps = prefs.getStringSet(KEY_ENABLED_APPS, emptySet()) ?: emptySet()
        if (!enabledApps.contains(pkg)) return

        val nativeEnabled = (prefs.getStringSet(KEY_HOOK_NATIVE, emptySet()) ?: emptySet()).contains(pkg)
        if (!nativeEnabled) return

        // Flutter detection: hook loadLibrary only for this selected app.
        // Only intercepts "flutter" — all other library names are ignored immediately.
        hookLoadLibrary(pkg)

        if (NativeHooks.loadLib(pkg)) {
            NativeHooks.nativeScanAndHook()
        }
    }

    private fun hookLoadLibrary(pkg: String) {
        tryHook(
            System::class.java, "loadLibrary",
            String::class.java,
            object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    // Fast-exit for every non-flutter library — no extra work done
                    val name = param.args[0] as? String ?: return
                    if ("flutter" in name) return

                    // libflutter.so is now guaranteed mapped (afterHookedMethod fires post-load)
                    Log.i(TAG, "[$pkg] flutter loaded — patching ssl_verify_peer_cert")
                    if (NativeHooks.loadLib(pkg)) {
                        NativeHooks.nativePatchFlutterForPkg(pkg)
                    }
                }
            }
        )
    }
}
