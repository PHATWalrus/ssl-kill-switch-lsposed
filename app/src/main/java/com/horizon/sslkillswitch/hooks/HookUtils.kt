package com.horizon.sslkillswitch.hooks

import android.util.Log
import de.robv.android.xposed.XposedHelpers

private const val TAG = "SSLKillSwitch"

fun tryHook(className: String, cl: ClassLoader, methodName: String, vararg paramTypesAndHook: Any) {
    try {
        XposedHelpers.findAndHookMethod(className, cl, methodName, *paramTypesAndHook)
        Log.d(TAG, "  [OK] $className.$methodName")
    } catch (e: XposedHelpers.ClassNotFoundError) {
        Log.v(TAG, "  [SKIP class] $className")
    } catch (e: NoSuchMethodError) {
        Log.w(TAG, "  [SKIP method] $className.$methodName")
    } catch (e: Throwable) {
        Log.e(TAG, "  [FAIL] $className.$methodName — ${e::class.simpleName}: ${e.message}")
    }
}

fun tryHook(clazz: Class<*>, methodName: String, vararg paramTypesAndHook: Any) {
    try {
        XposedHelpers.findAndHookMethod(clazz, methodName, *paramTypesAndHook)
        Log.d(TAG, "  [OK] ${clazz.name}.$methodName")
    } catch (e: NoSuchMethodError) {
        Log.w(TAG, "  [SKIP method] ${clazz.name}.$methodName")
    } catch (e: Throwable) {
        Log.e(TAG, "  [FAIL] ${clazz.name}.$methodName — ${e::class.simpleName}: ${e.message}")
    }
}

fun setField(obj: Any, fieldName: String, value: Any?) {
    var c: Class<*>? = obj.javaClass
    while (c != null) {
        try {
            val f = c.getDeclaredField(fieldName)
            f.isAccessible = true
            f.set(obj, value)
            Log.d(TAG, "  [field] ${obj.javaClass.simpleName}.$fieldName set")
            return
        } catch (_: NoSuchFieldException) { c = c.superclass }
    }
    Log.w(TAG, "  [field] NOT FOUND: ${obj.javaClass.simpleName}.$fieldName")
}
