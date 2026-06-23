package com.horizon.sslkillswitch

import android.util.Log
import com.horizon.sslkillswitch.config.FLUTTER_MODE_KOTLIN
import com.horizon.sslkillswitch.config.FLUTTER_MODE_NATIVE
import com.horizon.sslkillswitch.config.KEY_ENABLED_APPS
import com.horizon.sslkillswitch.config.KEY_HOOK_NATIVE
import com.horizon.sslkillswitch.config.KEY_LOGGING_ENABLED
import com.horizon.sslkillswitch.config.PREFS_NAME
import com.horizon.sslkillswitch.hooks.FlutterPatcher
import com.horizon.sslkillswitch.hooks.NativeHooks
import com.horizon.sslkillswitch.hooks.OkHttpHooks
import com.horizon.sslkillswitch.hooks.TrustManagerHooks
import com.horizon.sslkillswitch.hooks.WebViewHooks
import com.horizon.sslkillswitch.hooks.loggingEnabled
import com.horizon.sslkillswitch.hooks.tryHook
import com.horizon.sslkillswitch.xprefs.XposedPrefs
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.IXposedHookZygoteInit
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam

internal const val TAG = "SSLKillSwitch"
private const val MY_PKG = "com.horizon.sslkillswitch"
private const val FLUTTER_MODE_PREFIX = "flutter_mode_"

class MainHook : IXposedHookLoadPackage, IXposedHookZygoteInit {

    private val prefs = XposedPrefs.hook(MY_PKG, PREFS_NAME)
    @Volatile private var flutterPatched = false

    override fun initZygote(startupParam: IXposedHookZygoteInit.StartupParam) {
        Log.i(TAG, "initZygote — system-level SSL hooks to boot classpath")
        TrustManagerHooks.applySystem()
    }

    override fun handleLoadPackage(lpparam: LoadPackageParam) {
        val pkg = lpparam.packageName
        if (pkg == MY_PKG) {
            // Self-hook: flip ModuleStatus probes so our own UI knows the module is live.
            runCatching {
                val cls = lpparam.classLoader.loadClass("com.horizon.sslkillswitch.status.ModuleStatus")
                XposedHelpers.findAndHookMethod(cls, "isActive",
                    de.robv.android.xposed.XC_MethodReplacement.returnConstant(true))
                XposedHelpers.findAndHookMethod(cls, "frameworkVersion",
                    de.robv.android.xposed.XC_MethodReplacement.returnConstant(XposedBridge.getXposedVersion()))
            }.onFailure { Log.w(TAG, "self-hook ModuleStatus failed: ${it.message}") }
            return
        }

        prefs.reload()

        loggingEnabled = prefs.getBoolean(KEY_LOGGING_ENABLED, true)
        if (loggingEnabled) Log.i(TAG, "handleLoadPackage: $pkg")

        val cl = lpparam.classLoader

        // Java SSL hooks — all packages
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
/*
        // Native hooks — config-gated
        if (!prefs.isAvailable) {
            Log.w(TAG, "[$pkg] XSharedPreferences not readable — skipping native hooks")
            return
        }

        val enabledApps = prefs.getStringSet(KEY_ENABLED_APPS)
        Log.d(TAG, "[$pkg] enabledApps=$enabledApps")
        if (!enabledApps.contains(pkg)) {
            Log.d(TAG, "[$pkg] not in enabled apps — skipping native hooks")
            return
        }

        val nativeEnabled = prefs.getStringSet(KEY_HOOK_NATIVE).contains(pkg)
        if (!nativeEnabled) {
            Log.d(TAG, "[$pkg] native hook disabled")
            return
        }
*/
        val flutterMode = prefs.getString("$FLUTTER_MODE_PREFIX$pkg", FLUTTER_MODE_KOTLIN) ?: FLUTTER_MODE_KOTLIN
        Log.i(TAG, "[$pkg] flutter bypass mode: $flutterMode")

        hookLoadLibrary(pkg, cl, flutterMode)

        /*
        // nativeScanAndHook needs libs already mapped — defer to Application.onCreate
        tryHook(android.app.Application::class.java, "onCreate",
            object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val app = param.thisObject as android.content.Context
                    if (app.packageName != pkg) return
                    Log.i(TAG, "[$pkg] Application.onCreate — running native scan")
                    if (NativeHooks.loadLib(pkg)) {
                        NativeHooks.nativeScanAndHook()
                    } else {
                        Log.e(TAG, "[$pkg] native lib unavailable — skipping nativeScanAndHook")
                    }
                }
            }
        )*/
    }

    private fun hookLoadLibrary(pkg: String, cl: ClassLoader, mode: String) {
        Log.i(TAG, "[$pkg] installing System.loadLibrary hook — mode=$mode")
        hookLoadLibraryKotlin(pkg, cl)
        /*
        when (mode) {
            FLUTTER_MODE_KOTLIN -> hookLoadLibraryKotlin(pkg, cl)
            else                -> hookLoadLibraryNative(pkg)
        }*/
    }

    // File-patch mode: intercept loadLibrary before flutter is mapped, patch on disk, load patched copy.
    // Primary hook: Runtime.loadLibrary0(ClassLoader, String) — carries the real ClassLoader so the
    // patched lib loads in the correct namespace. Falls back to System.loadLibrary if not found
    // (Android 10+ changed the signature to 3 params).
    private fun hookLoadLibraryKotlin(pkg: String, cl: ClassLoader) {
        val hook = object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                if (flutterPatched) return

                // Last String arg is either:
                //   • a library name  ("flutter")          — loadLibrary0 / System.loadLibrary
                //   • an absolute path ("/data/.../libflutter.so") — System.load
                val lastStr = param.args.filterIsInstance<String>().lastOrNull() ?: return
                if ("flutter" !in lastStr) return

                Log.i(TAG, "[$pkg] flutter load intercepted: $lastStr")

                // If the arg is an absolute path (System.load), use it directly;
                // otherwise resolve via ClassLoader strategies (System.loadLibrary / loadLibrary0).
                val libPath = if (java.io.File(lastStr).isAbsolute) {
                    lastStr
                } else {
                    FlutterPatcher.findLibFlutterPath(cl) ?: run {
                        Log.e(TAG, "[$pkg] Cannot resolve libflutter.so path — falling back to original load")
                        return
                    }
                }

                val patchedPath = FlutterPatcher.patch(libPath, pkg) ?: run {
                    Log.e(TAG, "[$pkg] Kotlin flutter patch failed — falling back to original load")
                    return
                }

                // Prefer the ClassLoader from args (loadLibrary0 case) so the native lib
                // resolves symbols in the right namespace; fall back to the app ClassLoader.
                val targetCl = param.args.firstOrNull { it is ClassLoader } as? ClassLoader ?: cl

                if (FlutterPatcher.loadPatched(patchedPath, targetCl, pkg)) {
                    flutterPatched = true
                    param.result = null  // skip original loadLibrary call
                    Log.i(TAG, "[$pkg] Kotlin flutter patch active — ssl_verify_peer_cert returns 0")
                } else {
                    Log.e(TAG, "[$pkg] all load strategies failed — proceeding with original load")
                }
            }
        }

        // Hook every loadLibrary0 variant found in this Runtime — covers:
        //   API 26-28: loadLibrary0(ClassLoader, String)          — 2 params
        //   API 29+:   loadLibrary0(ClassLoader, Class, String)   — 3 params
        // The hook extracts lib name as last String arg and ClassLoader as first ClassLoader arg,
        // so the same callback body handles all variants.
        val loadLibrary0Methods = Runtime::class.java.declaredMethods.filter {
            it.name == "loadLibrary0"
        }

        var hookedViaLoadLibrary0 = false
        for (m in loadLibrary0Methods) {
            runCatching {
                XposedBridge.hookMethod(m, hook)
                Log.i(TAG, "[$pkg] Runtime.loadLibrary0(${m.parameterTypes.map { it.simpleName }}) hooked")
                hookedViaLoadLibrary0 = true
            }.onFailure {
                Log.w(TAG, "[$pkg] Runtime.loadLibrary0 hook failed: ${it.message}")
            }
        }

        if (!hookedViaLoadLibrary0) {
            // Fallback: System.loadLibrary(String). No ClassLoader in args, uses lpparam.classLoader.
            Log.i(TAG, "[$pkg] no loadLibrary0 hooked — falling back to System.loadLibrary")
            tryHook(System::class.java, "loadLibrary", String::class.java, hook)
        }

        // Also hook System.load(absolutePath) — some embeddings call this directly
        // with the full path to libflutter.so instead of using loadLibrary.
        tryHook(System::class.java, "load", String::class.java, hook)
    }

    // In-memory mode: intercept AFTER load, scan mapped pages, patch via /proc/self/mem.
    private fun hookLoadLibraryNative(pkg: String) {
        tryHook(
            System::class.java, "loadLibrary",
            String::class.java,
            object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    val name = param.args[0] as? String ?: return
                    if ("flutter" !in name) return

                    Log.i(TAG, "[$pkg] flutter loaded — native in-memory patch")
                    if (NativeHooks.loadLib(pkg)) {
                        NativeHooks.nativePatchFlutterForPkg(pkg)
                    }
                }
            }
        )
    }
}
