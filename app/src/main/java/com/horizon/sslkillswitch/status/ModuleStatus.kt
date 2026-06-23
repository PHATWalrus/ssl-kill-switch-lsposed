package com.horizon.sslkillswitch.status

/**
 * Self-hook probe. These return the "inactive" defaults when called from the
 * normal (unhooked) app process. MainHook hooks them inside our own package to
 * return the active values, so the UI can tell whether the module is actually
 * loaded into this process by LSPosed (i.e. our own app is in the module scope).
 */
object ModuleStatus {
    @JvmStatic fun isActive(): Boolean = false
    @JvmStatic fun frameworkVersion(): Int = -1
}
