package com.horizon.sslkillswitch.ui

import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.horizon.sslkillswitch.databinding.ActivityLogViewerBinding
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * In-app logcat viewer scoped to the module tags. Reads via `su` (root) so it
 * works on Android 10+ where apps can't read other processes' logs without it.
 */
class LogViewerActivity : AppCompatActivity() {

    private lateinit var b: ActivityLogViewerBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        b = ActivityLogViewerBinding.inflate(layoutInflater)
        setContentView(b.root)

        b.btnRefreshLog.setOnClickListener { loadLog() }
        b.btnClearLog.setOnClickListener { clearLog() }
    }

    override fun onResume() {
        super.onResume()
        loadLog()
    }

    private fun loadLog() {
        CoroutineScope(Dispatchers.IO).launch {
            val out = runSu("logcat -d -v time -s SSLKillSwitch:* ssl_kill_switch:*")
            withContext(Dispatchers.Main) {
                b.tvLog.text = out.trim().ifBlank { "(no log lines — is the module active and logging enabled?)" }
                if (b.switchAutoScroll.isChecked) {
                    b.logScroll.post { b.logScroll.fullScroll(View.FOCUS_DOWN) }
                }
            }
        }
    }

    private fun clearLog() {
        CoroutineScope(Dispatchers.IO).launch {
            runSu("logcat -c")
            withContext(Dispatchers.Main) {
                b.tvLog.text = "(cleared)"
                toast("Log buffer cleared")
            }
        }
    }

    private fun runSu(cmd: String): String = try {
        val proc = Runtime.getRuntime().exec(arrayOf("su", "-c", cmd))
        val out = proc.inputStream.bufferedReader().readText()
        proc.waitFor()
        out
    } catch (e: Exception) {
        "Error running '$cmd': ${e.message}\n(root required for log access on Android 10+)"
    }

    private fun toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
}
