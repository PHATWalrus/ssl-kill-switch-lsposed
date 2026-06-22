package com.horizon.sslkillswitch

import android.util.Log
import com.horizon.sslkillswitch.config.FLUTTER_MODE_KOTLIN
import com.horizon.sslkillswitch.config.FLUTTER_MODE_NATIVE
import com.horizon.sslkillswitch.config.KEY_ENABLED_APPS
import com.horizon.sslkillswitch.config.KEY_HOOK_NATIVE
import com.horizon.sslkillswitch.config.KEY_LOGGING_ENABLED
import com.horizon.sslkillswitch.hooks.FlutterPatcher
import com.horizon.sslkillswitch.hooks.NativeHooks
import com.horizon.sslkillswitch.hooks.OkHttpHooks
import com.horizon.sslkillswitch.hooks.RemoteConfig
import com.horizon.sslkillswitch.hooks.TrustManagerHooks
import com.horizon.sslkillswitch.hooks.WebViewHooks
import com.horizon.sslkillswitch.hooks.loggingEnabled
import com.horizon.sslkillswitch.hooks.tryHook
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.IXposedHookZygoteInit
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam

internal const val TAG = "SSLKillSwitch"

private const val FLUTTER_MODE_PREFIX = "flutter_mode_"

class MainHook : IXposedHookLoadPackage, IXposedHookZygoteInit {

    override fun initZygote(startupParam: IXposedHookZygoteInit.StartupParam) {
        Log.i(TAG, "initZygote — system-level SSL hooks to boot classpath")
        TrustManagerHooks.applySystem()
    }

    override fun handleLoadPackage(lpparam: LoadPackageParam) {
        val pkg = lpparam.packageName
        if (pkg == "com.horizon.sslkillswitch") return

        if (loggingEnabled) Log.i(TAG, "handleLoadPackage: $pkg")

        val cl = lpparam.classLoader

        // ── 1. Java SSL hooks — ALL packages, no config dependency ───────────
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

        // ── 2. Native hooks — deferred to Application.onCreate ───────────────
        // We need a Context to query the ContentProvider that serves our config.
        // XSharedPreferences reads the prefs file directly; SELinux blocks all
        // cross-app file access (stat, open, read) from the hooked process.
        // ContentProvider queries cross via Binder — SELinux allows this.
        // Application.onCreate fires before any app code and gives us param.thisObject as Context.
        tryHook(android.app.Application::class.java, "onCreate",
            object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val app = param.thisObject as android.content.Context
                    // Hook fires for every app; guard to our target package.
                    if (app.packageName != pkg) return
                    Log.i(TAG, "[$pkg] Application.onCreate — reading config via ContentProvider")
                    installNativeHooksIfEnabled(pkg, cl, app)
                }
            }
        )
    }

    private fun installNativeHooksIfEnabled(pkg: String, cl: ClassLoader, ctx: android.content.Context) {
        val config = RemoteConfig.read(ctx)

        loggingEnabled = config.getBoolean(KEY_LOGGING_ENABLED, true)

        val enabledApps = config.getStringSet(KEY_ENABLED_APPS)
        Log.d(TAG, "[$pkg] enabledApps=$enabledApps")

        if (!enabledApps.contains(pkg)) {
            Log.d(TAG, "[$pkg] not in enabled apps — skipping native hooks")
            return
        }

        val nativeEnabled = config.getStringSet(KEY_HOOK_NATIVE).contains(pkg)
        if (!nativeEnabled) {
            Log.d(TAG, "[$pkg] native hook disabled — skipping loadLibrary hook + native scan")
            return
        }

        val flutterMode = config.getString("$FLUTTER_MODE_PREFIX$pkg", FLUTTER_MODE_NATIVE)
            ?: FLUTTER_MODE_NATIVE
        Log.i(TAG, "[$pkg] flutter bypass mode: $flutterMode")

        hookLoadLibrary(pkg, cl, flutterMode)

        Log.i(TAG, "[$pkg] loading native ssl_kill_switch lib and running initial scan")
        if (NativeHooks.loadLib(pkg)) {
            NativeHooks.nativeScanAndHook()
        } else {
            Log.e(TAG, "[$pkg] native lib unavailable — skipping nativeScanAndHook")
        }
    }

    private fun hookLoadLibrary(pkg: String, cl: ClassLoader, mode: String) {
        Log.i(TAG, "[$pkg] installing System.loadLibrary hook — mode=$mode")
        when (mode) {
            FLUTTER_MODE_KOTLIN -> hookLoadLibraryKotlin(pkg, cl)
            else                -> hookLoadLibraryNative(pkg)
        }
    }

    // File-patch mode: intercept BEFORE load, patch on disk, load patched copy, skip original.
    private fun hookLoadLibraryKotlin(pkg: String, cl: ClassLoader) {
        tryHook(
            System::class.java, "loadLibrary",
            String::class.java,
            object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val name = param.args[0] as? String ?: return
                    if ("flutter" !in name) return

                    Log.i(TAG, "[$pkg] flutter loadLibrary intercepted — Kotlin file-patch mode")

                    val libPath = FlutterPatcher.findLibFlutterPath(cl) ?: run {
                        Log.e(TAG, "[$pkg] Cannot resolve libflutter.so path — falling back to original load")
                        return
                    }

                    val patchedPath = FlutterPatcher.patch(libPath, pkg) ?: run {
                        Log.e(TAG, "[$pkg] Kotlin flutter patch failed — falling back to original load")
                        return
                    }

                    try {
                        System.load(patchedPath)
                        param.result = null  // skip System.loadLibrary("flutter")
                        Log.i(TAG, "[$pkg] Kotlin flutter patch active — ssl_verify_peer_cert returns 0")
                    } catch (e: UnsatisfiedLinkError) {
                        Log.e(TAG, "[$pkg] System.load($patchedPath) failed: ${e.message}")
                        // Don't set result — original loadLibrary proceeds normally
                    }
                }
            }
        )
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
