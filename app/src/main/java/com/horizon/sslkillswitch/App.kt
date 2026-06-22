package com.horizon.sslkillswitch

import android.app.Application
import com.horizon.sslkillswitch.config.ConfigWriter

class App : Application() {
    override fun onCreate() {
        super.onCreate()
        // Force prefs file creation on first launch so XSharedPreferences (via LSPosed service)
        // can find it. SharedPreferences only writes to disk when there is an actual change —
        // calling ensurePrefsFile writes the initial defaults if no prefs exist yet.
        ConfigWriter.ensurePrefsFile(this)
    }
}
