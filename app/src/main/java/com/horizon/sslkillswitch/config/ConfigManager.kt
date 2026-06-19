package com.horizon.sslkillswitch.config

import android.content.Context

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

private const val DOMAIN_PREFIX = "domains_"

object ConfigWriter {

    // MODE_PRIVATE is correct. LSPosed daemon (root) serves this file to XSharedPreferences
    // in hooked processes — MODE_WORLD_READABLE is blocked by Android 7+ and not needed.
    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    // ── App enabled ───────────────────────────────────────────────────────────

    fun setAppEnabled(context: Context, packageName: String, enabled: Boolean) {
        val p = prefs(context)
        val apps = p.getStringSet(KEY_ENABLED_APPS, mutableSetOf())!!.toMutableSet()
        if (enabled) {
            apps.add(packageName)
            // Default: enable all hook categories when first enabling an app
            val edit = p.edit()
            for (key in ALL_HOOK_KEYS) {
                val cats = p.getStringSet(key, mutableSetOf())!!.toMutableSet()
                if (!cats.contains(packageName)) {
                    cats.add(packageName)
                    edit.putStringSet(key, cats)
                }
            }
            edit.apply()
        } else {
            apps.remove(packageName)
        }
        p.edit().putStringSet(KEY_ENABLED_APPS, apps).apply()
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
        p.edit().putStringSet(categoryKey, apps).apply()
    }

    fun isHookCategoryEnabled(context: Context, categoryKey: String, packageName: String): Boolean =
        prefs(context).getStringSet(categoryKey, emptySet())?.contains(packageName) == true

    fun getHookCategoryApps(context: Context, categoryKey: String): Set<String> =
        prefs(context).getStringSet(categoryKey, emptySet()) ?: emptySet()

    // ── Domains ───────────────────────────────────────────────────────────────

    fun setDomainsForApp(context: Context, packageName: String, domains: Set<String>) {
        prefs(context).edit().putStringSet("$DOMAIN_PREFIX$packageName", domains).apply()
    }

    fun getDomainsForApp(context: Context, packageName: String): Set<String> =
        prefs(context).getStringSet("$DOMAIN_PREFIX$packageName", emptySet()) ?: emptySet()

    // ── Proxy ─────────────────────────────────────────────────────────────────

    fun setProxyConfig(context: Context, host: String, port: Int, enabled: Boolean) {
        prefs(context).edit()
            .putString(KEY_PROXY_HOST, host)
            .putInt(KEY_PROXY_PORT, port)
            .putBoolean(KEY_PROXY_ENABLED, enabled)
            .apply()
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
        prefs(context).edit().putBoolean(KEY_LOGGING_ENABLED, enabled).apply()
    }
}
