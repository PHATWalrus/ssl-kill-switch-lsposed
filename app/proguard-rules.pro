# Xposed API
-keep class de.robv.android.xposed.** { *; }

# Entry point — must keep the exact class name because LSPosed loads it from assets/xposed_init
-keep class com.horizon.sslkillswitch.MainHook { *; }

# Application class referenced in AndroidManifest.xml
-keep class com.horizon.sslkillswitch.App { *; }

# Hook engine, config, prefs
-keep class com.horizon.sslkillswitch.hooks.** { *; }
-keep class com.horizon.sslkillswitch.config.** { *; }
-keep class com.horizon.sslkillswitch.xprefs.** { *; }

# Native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep all implementers of Xposed entry interfaces
-keep class * implements de.robv.android.xposed.IXposedHookLoadPackage { *; }
-keep class * implements de.robv.android.xposed.IXposedHookZygoteInit { *; }
