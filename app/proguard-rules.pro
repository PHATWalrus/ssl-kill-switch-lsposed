-keep class de.robv.android.xposed.** { *; }
-keepclassmembers class * implements de.robv.android.xposed.IXposedHookLoadPackage {
    public void handleLoadPackage(de.robv.android.xposed.callbacks.XC_LoadPackage$LoadPackageParam);
}
