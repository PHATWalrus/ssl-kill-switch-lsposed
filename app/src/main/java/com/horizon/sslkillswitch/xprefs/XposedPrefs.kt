package com.horizon.sslkillswitch.xprefs

import de.robv.android.xposed.XSharedPreferences

class XposedPrefs private constructor(
    private val packageName: String,
    private val prefsName: String
) {
    private var xsp = newXsp()

    private fun newXsp() = XSharedPreferences(packageName, prefsName)

    val isAvailable: Boolean get() = xsp.file.canRead()

    // Recreate instead of reload() — stale XSharedPreferences instances don't pick up
    // file changes made after initial construction.
    fun reload() {
        xsp = newXsp()
    }

    fun getBoolean(key: String, def: Boolean = false): Boolean = xsp.getBoolean(key, def)
    fun getString(key: String, def: String? = null): String? = xsp.getString(key, def)
    fun getStringSet(key: String, def: Set<String> = emptySet()): Set<String> =
        xsp.getStringSet(key, def) ?: def

    companion object {
        fun hook(packageName: String, prefsName: String) = XposedPrefs(packageName, prefsName)
    }
}
