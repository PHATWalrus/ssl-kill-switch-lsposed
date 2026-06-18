package com.horizon.sslkillswitch.ui

import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.horizon.sslkillswitch.config.ConfigWriter
import com.horizon.sslkillswitch.databinding.ActivityMainBinding
import com.horizon.sslkillswitch.iptables.IptablesManager

class MainActivity : AppCompatActivity() {

    private lateinit var b: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        b = ActivityMainBinding.inflate(layoutInflater)
        setContentView(b.root)

        loadConfig()
        setupListeners()
    }

    private fun loadConfig() {
        b.etProxyHost.setText(ConfigWriter.getProxyHost(this))
        b.etProxyPort.setText(ConfigWriter.getProxyPort(this).toString())
        b.switchProxy.isChecked = ConfigWriter.isProxyEnabled(this)
        b.switchNativeHooks.isChecked = true
    }

    private fun setupListeners() {
        b.btnSelectApps.setOnClickListener {
            startActivity(Intent(this, AppListActivity::class.java))
        }

        b.btnApplyIptables.setOnClickListener {
            applyIptables()
        }

        b.btnFlushIptables.setOnClickListener {
            IptablesManager.removeAllRules()
                .onSuccess { toast("iptables rules flushed") }
                .onFailure { toast("Flush failed: ${it.message}") }
        }

        b.btnDumpNat.setOnClickListener {
            val dump = IptablesManager.dumpNatTable()
            b.tvNatDump.text = dump
        }

        b.switchProxy.setOnCheckedChangeListener { _, checked ->
            saveProxyConfig()
        }

        b.switchNativeHooks.setOnCheckedChangeListener { _, checked ->
            ConfigWriter.setNativeHooksEnabled(this, checked)
        }
    }

    private fun applyIptables() {
        val host = b.etProxyHost.text.toString().trim()
        val port = b.etProxyPort.text.toString().toIntOrNull() ?: 8080

        if (host.isEmpty()) {
            toast("Enter proxy host")
            return
        }

        saveProxyConfig()

        val enabledApps = ConfigWriter.getEnabledApps(this)
        if (enabledApps.isEmpty()) {
            toast("No apps selected")
            return
        }

        var applied = 0
        var failed = 0
        for (pkg in enabledApps) {
            val uid = IptablesManager.getAppUid(this, pkg) ?: continue
            val rule = com.horizon.sslkillswitch.iptables.IptablesRule(uid, pkg, host, port)
            IptablesManager.applyRule(rule)
                .onSuccess { applied++ }
                .onFailure { failed++ }
        }
        toast("Applied $applied rules, $failed failed")
    }

    private fun saveProxyConfig() {
        val host = b.etProxyHost.text.toString().trim()
        val port = b.etProxyPort.text.toString().toIntOrNull() ?: 8080
        ConfigWriter.setProxyConfig(this, host, port, b.switchProxy.isChecked)
    }

    private fun toast(msg: String) =
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
}
