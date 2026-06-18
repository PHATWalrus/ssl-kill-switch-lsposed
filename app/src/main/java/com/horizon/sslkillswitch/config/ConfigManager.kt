package com.horizon.sslkillswitch.config

import android.content.Context
import de.robv.android.xposed.XSharedPreferences

const val PREFS_NAME = "ssl_ks_config"
const val KEY_ENABLED_APPS = "enabled_apps"
const val KEY_PROXY_HOST = "proxy_host"
const val KEY_PROXY_PORT = "proxy_port"
const val KEY_PROXY_ENABLED = "proxy_enabled"
const val KEY_NATIVE_HOOKS = "native_hooks_enabled"

private const val DOMAIN_PREFIX = "domains_"

// Read-side: used from hooked process
class HookConfig(private val prefs: XSharedPreferences) {

    fun isAppEnabled(packageName: String): Boolean {
        prefs.reload()
        return prefs.getStringSet(KEY_ENABLED_APPS, emptySet())?.contains(packageName) == true
    }

    fun getDomainsForApp(packageName: String): Set<String> {
        prefs.reload()
        return prefs.getStringSet("$DOMAIN_PREFIX$packageName", emptySet()) ?: emptySet()
    }

    fun isDomainAllowed(packageName: String, host: String): Boolean {
        val domains = getDomainsForApp(packageName)
        return domains.isEmpty() || domains.any { host.endsWith(it) }
    }

    fun isNativeHooksEnabled(): Boolean {
        prefs.reload()
        return prefs.getBoolean(KEY_NATIVE_HOOKS, true)
    }

    companion object {
        @Volatile private var instance: HookConfig? = null

        fun get(modulePackage: String): HookConfig {
            return instance ?: synchronized(this) {
                instance ?: HookConfig(
                    XSharedPreferences(modulePackage, PREFS_NAME).also {
                        it.makeWorldReadable()
                    }
                ).also { instance = it }
            }
        }
    }
}

// Write-side: used from module UI (runs as app itself)
object ConfigWriter {

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun setAppEnabled(context: Context, packageName: String, enabled: Boolean) {
        val p = prefs(context)
        val apps = p.getStringSet(KEY_ENABLED_APPS, mutableSetOf())!!.toMutableSet()
        if (enabled) apps.add(packageName) else apps.remove(packageName)
        p.edit().putStringSet(KEY_ENABLED_APPS, apps).apply()
    }

    fun isAppEnabled(context: Context, packageName: String): Boolean {
        return prefs(context).getStringSet(KEY_ENABLED_APPS, emptySet())?.contains(packageName) == true
    }

    fun getEnabledApps(context: Context): Set<String> {
        return prefs(context).getStringSet(KEY_ENABLED_APPS, emptySet()) ?: emptySet()
    }

    fun setDomainsForApp(context: Context, packageName: String, domains: Set<String>) {
        prefs(context).edit().putStringSet("$DOMAIN_PREFIX$packageName", domains).apply()
    }

    fun getDomainsForApp(context: Context, packageName: String): Set<String> {
        return prefs(context).getStringSet("$DOMAIN_PREFIX$packageName", emptySet()) ?: emptySet()
    }

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

    fun setNativeHooksEnabled(context: Context, enabled: Boolean) {
        prefs(context).edit().putBoolean(KEY_NATIVE_HOOKS, enabled).apply()
    }
}
