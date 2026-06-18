package com.horizon.sslkillswitch.hooks

import io.github.libxposed.api.XposedInterface
import java.lang.reflect.Method

fun tryHook(
    xposed: XposedInterface,
    className: String,
    cl: ClassLoader,
    methodName: String,
    paramTypes: Array<Class<*>>,
    hook: XposedInterface.Hooker
) {
    try {
        val m: Method = cl.loadClass(className).getDeclaredMethod(methodName, *paramTypes)
        xposed.hook(m).intercept(hook)
    } catch (_: Throwable) {}
}

fun tryHook(
    xposed: XposedInterface,
    clazz: Class<*>,
    methodName: String,
    paramTypes: Array<Class<*>>,
    hook: XposedInterface.Hooker
) {
    try {
        val m: Method = clazz.getDeclaredMethod(methodName, *paramTypes)
        xposed.hook(m).intercept(hook)
    } catch (_: Throwable) {}
}

fun setField(obj: Any, fieldName: String, value: Any?) {
    var c: Class<*>? = obj.javaClass
    while (c != null) {
        try {
            val f = c.getDeclaredField(fieldName)
            f.isAccessible = true
            f.set(obj, value)
            return
        } catch (_: NoSuchFieldException) { c = c.superclass }
    }
}
