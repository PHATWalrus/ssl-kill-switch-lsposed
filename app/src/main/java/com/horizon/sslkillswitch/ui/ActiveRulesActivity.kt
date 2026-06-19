package com.horizon.sslkillswitch.ui

import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.horizon.sslkillswitch.databinding.ActivityActiveRulesBinding
import com.horizon.sslkillswitch.iptables.IptablesManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class ActiveRulesActivity : AppCompatActivity() {

    private lateinit var b: ActivityActiveRulesBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        b = ActivityActiveRulesBinding.inflate(layoutInflater)
        setContentView(b.root)

        b.btnFlushAll.setOnClickListener {
            IptablesManager.flushAll()
                .onSuccess {
                    refreshRules()
                    b.tvNatDump.text = "— flushed —"
                    toast("All rules flushed")
                }
                .onFailure { toast("Flush failed: ${it.message}") }
        }

        b.btnRefreshDump.setOnClickListener { loadNatDump() }
    }

    override fun onResume() {
        super.onResume()
        refreshRules()
        loadNatDump()
    }

    private fun refreshRules() {
        val rules = IptablesManager.getActiveRules()
        b.tvActiveRules.text = if (rules.isEmpty()) {
            "No active rules"
        } else {
            rules.joinToString("\n\n") { r ->
                "pkg : ${r.packageName}\nuid : ${r.uid}\ndst : ${r.proxyHost}:${r.proxyPort}"
            }
        }
    }

    private fun loadNatDump() {
        b.tvNatDump.text = "Loading…"
        CoroutineScope(Dispatchers.IO).launch {
            val dump = IptablesManager.dumpNatTable()
            withContext(Dispatchers.Main) {
                b.tvNatDump.text = dump.trim().ifBlank { "(empty)" }
            }
        }
    }

    private fun toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
}
