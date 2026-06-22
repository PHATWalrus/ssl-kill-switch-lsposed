package com.horizon.sslkillswitch.hooks

import android.content.Context
import android.net.Uri
import android.util.Log
import com.horizon.sslkillswitch.ConfigProvider

private const val TAG = "SSLKillSwitch"

object RemoteConfig {

    private val URI = Uri.parse("content://${ConfigProvider.AUTHORITY}/prefs")

    class Config(private val m: Map<String, String>) {
        fun getBoolean(key: String, default: Boolean = false): Boolean =
            when (m[key]) { "1", "true" -> true; "0", "false" -> false; else -> default }

        fun getString(key: String, default: String? = null): String? = m[key] ?: default

        fun getStringSet(key: String, default: Set<String> = emptySet()): Set<String> {
            val raw = m[key] ?: return default
            return if (raw.isEmpty()) default
            else raw.split(ConfigProvider.SET_DELIM).filter { it.isNotEmpty() }.toSet()
        }
    }

    fun read(ctx: Context): Config {
        val map = mutableMapOf<String, String>()
        runCatching {
            ctx.contentResolver.query(URI, null, null, null, null)?.use { cursor ->
                val ki = cursor.getColumnIndexOrThrow("k")
                val vi = cursor.getColumnIndexOrThrow("v")
                while (cursor.moveToNext()) map[cursor.getString(ki)] = cursor.getString(vi) ?: ""
            }
        }.onFailure { Log.e(TAG, "RemoteConfig.read failed: ${it.message}") }
        Log.d(TAG, "RemoteConfig: ${map.size} keys — ${map.keys}")
        return Config(map)
    }
}
