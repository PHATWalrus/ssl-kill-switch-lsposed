package com.horizon.sslkillswitch.config

import android.content.Context
import android.util.Log
import java.io.File

const val PREFS_NAME        = "ssl_ks_config"
const val KEY_ENABLED_APPS  = "enabled_apps"
const val KEY_PROXY_HOST    = "proxy_host"
const val KEY_PROXY_PORT    = "proxy_port"
const val KEY_PROXY_ENABLED = "proxy_enabled"

// Per-app hook category keys (Set<String> of package names)
const val KEY_HOOK_TRUSTMANAGER = "hooks_tm"
const val KEY_HOOK_OKHTTP       = "hooks_okhttp"
const val KEY_HOOK_WEBVIEW      = "hooks_webview"
const val KEY_HOOK_NATIVE       = "hooks_native"

val ALL_HOOK_KEYS = listOf(KEY_HOOK_TRUSTMANAGER, KEY_HOOK_OKHTTP, KEY_HOOK_WEBVIEW, KEY_HOOK_NATIVE)

const val KEY_LOGGING_ENABLED   = "logging_enabled"

// Per-app flutter bypass mode values
const val FLUTTER_MODE_NATIVE = "native"   // in-memory patch via C++ (default)
const val FLUTTER_MODE_KOTLIN = "kotlin"   // file patch via Kotlin + System.load

private const val DOMAIN_PREFIX        = "domains_"
private const val FLUTTER_MODE_PREFIX  = "flutter_mode_"
private const val TAG                  = "SSLKillSwitch"

object ConfigWriter {

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    /**
     * commit() + setReadable(true, false) after every write.
     *
     * XSharedPreferences in LSPosed reads the file via its root daemon. That works
     * regardless of unix permissions, BUT older LSPosed builds / compat paths fall
     * back to direct file read. Making the file world-readable ensures both paths work.
     *
     * commit() is used instead of apply() so the file is on disk before setReadable()
     * is called — apply() is async and the file may not exist yet at chmod time.
     */
    private fun commit(context: Context, block: android.content.SharedPreferences.Editor.() -> Unit) {
        val ok = prefs(context).edit().apply(block).run { commit() }
        if (!ok) Log.e(TAG, "ConfigWriter: SharedPreferences.commit() returned false")
        makeReadable(context)
    }

    private fun makeReadable(context: Context) {
        runCatching {
            val f = File(context.applicationInfo.dataDir, "shared_prefs/$PREFS_NAME.xml")
            val readable = f.setReadable(true, false)
            Log.d(TAG, "ConfigWriter: makeReadable ${f.absolutePath} → $readable (exists=${f.exists()})")
        }.onFailure {
            Log.w(TAG, "ConfigWriter: makeReadable failed — ${it.message}")
        }
    }

    // ── App enabled ───────────────────────────────────────────────────────────

    fun setAppEnabled(context: Context, packageName: String, enabled: Boolean) {
        val p = prefs(context)
        val apps = p.getStringSet(KEY_ENABLED_APPS, mutableSetOf())!!.toMutableSet()
        if (enabled) {
            apps.add(packageName)
            // Enable all hook categories when first enabling an app
            commit(context) {
                for (key in ALL_HOOK_KEYS) {
                    val cats = p.getStringSet(key, mutableSetOf())!!.toMutableSet()
                    cats.add(packageName)
                    putStringSet(key, cats)
                }
                putStringSet(KEY_ENABLED_APPS, apps)
            }
        } else {
            apps.remove(packageName)
            commit(context) { putStringSet(KEY_ENABLED_APPS, apps) }
        }
        Log.d(TAG, "ConfigWriter: setAppEnabled $packageName=$enabled → enabledApps=$apps")
    }

    fun isAppEnabled(context: Context, packageName: String): Boolean =
        prefs(context).getStringSet(KEY_ENABLED_APPS, emptySet())?.contains(packageName) == true

    fun getEnabledApps(context: Context): Set<String> =
        prefs(context).getStringSet(KEY_ENABLED_APPS, emptySet()) ?: emptySet()

    // ── Hook categories ───────────────────────────────────────────────────────

    fun setHookCategory(context: Context, categoryKey: String, packageName: String, enabled: Boolean) {
        val p = prefs(context)
        val apps = p.getStringSet(categoryKey, mutableSetOf())!!.toMutableSet()
        if (enabled) apps.add(packageName) else apps.remove(packageName)
        commit(context) { putStringSet(categoryKey, apps) }
        Log.d(TAG, "ConfigWriter: setHookCategory $categoryKey/$packageName=$enabled")
    }

    fun isHookCategoryEnabled(context: Context, categoryKey: String, packageName: String): Boolean =
        prefs(context).getStringSet(categoryKey, emptySet())?.contains(packageName) == true

    fun getHookCategoryApps(context: Context, categoryKey: String): Set<String> =
        prefs(context).getStringSet(categoryKey, emptySet()) ?: emptySet()

    // ── Domains ───────────────────────────────────────────────────────────────

    fun setDomainsForApp(context: Context, packageName: String, domains: Set<String>) {
        commit(context) { putStringSet("$DOMAIN_PREFIX$packageName", domains) }
    }

    fun getDomainsForApp(context: Context, packageName: String): Set<String> =
        prefs(context).getStringSet("$DOMAIN_PREFIX$packageName", emptySet()) ?: emptySet()

    // ── Flutter bypass mode ───────────────────────────────────────────────────

    fun getFlutterMode(context: Context, packageName: String): String =
        prefs(context).getString("$FLUTTER_MODE_PREFIX$packageName", FLUTTER_MODE_NATIVE) ?: FLUTTER_MODE_NATIVE

    fun setFlutterMode(context: Context, packageName: String, mode: String) {
        commit(context) { putString("$FLUTTER_MODE_PREFIX$packageName", mode) }
        Log.d(TAG, "ConfigWriter: setFlutterMode $packageName=$mode")
    }

    // ── Proxy ─────────────────────────────────────────────────────────────────

    fun setProxyConfig(context: Context, host: String, port: Int, enabled: Boolean) {
        commit(context) {
            putString(KEY_PROXY_HOST, host)
            putInt(KEY_PROXY_PORT, port)
            putBoolean(KEY_PROXY_ENABLED, enabled)
        }
    }

    fun getProxyHost(context: Context): String =
        prefs(context).getString(KEY_PROXY_HOST, "192.168.1.1") ?: "192.168.1.1"

    fun getProxyPort(context: Context): Int =
        prefs(context).getInt(KEY_PROXY_PORT, 8080)

    fun isProxyEnabled(context: Context): Boolean =
        prefs(context).getBoolean(KEY_PROXY_ENABLED, false)

    // ── Logging ───────────────────────────────────────────────────────────────

    fun isLoggingEnabled(context: Context): Boolean =
        prefs(context).getBoolean(KEY_LOGGING_ENABLED, true)

    fun setLoggingEnabled(context: Context, enabled: Boolean) {
        commit(context) { putBoolean(KEY_LOGGING_ENABLED, enabled) }
    }
}
