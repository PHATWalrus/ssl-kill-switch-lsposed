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

        refreshRules()

        b.btnFlushAll.setOnClickListener {
            IptablesManager.flushAll()
                .onSuccess {
                    refreshRules()
                    b.tvNatDump.text = ""
                    toast("All rules flushed")
                }
                .onFailure { toast("Flush failed: ${it.message}") }
        }

        b.btnRefreshDump.setOnClickListener {
            CoroutineScope(Dispatchers.IO).launch {
                val dump = IptablesManager.dumpNatTable()
                withContext(Dispatchers.Main) { b.tvNatDump.text = dump }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        refreshRules()
    }

    private fun refreshRules() {
        val rules = IptablesManager.getActiveRules()
        b.tvActiveRules.text = if (rules.isEmpty()) {
            "No active rules"
        } else {
            rules.joinToString("\n") { "uid=${it.uid}  ${it.packageName}  →  ${it.proxyHost}:${it.proxyPort}" }
        }
    }

    private fun toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
}
