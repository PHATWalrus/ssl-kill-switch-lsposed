package com.horizon.sslkillswitch.ui

import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.chip.Chip
import com.horizon.sslkillswitch.config.ConfigWriter
import com.horizon.sslkillswitch.databinding.ActivityMainBinding
import com.horizon.sslkillswitch.iptables.IptablesManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {

    private lateinit var b: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        b = ActivityMainBinding.inflate(layoutInflater)
        setContentView(b.root)
        loadConfig()
        setupListeners()
    }

    override fun onResume() {
        super.onResume()
        refreshSelectedApps()
    }

    private fun loadConfig() {
        b.etProxyHost.setText(ConfigWriter.getProxyHost(this))
        b.etProxyPort.setText(ConfigWriter.getProxyPort(this).toString())
        b.switchProxy.isChecked = ConfigWriter.isProxyEnabled(this)
        b.switchNativeHooks.isChecked = true
        b.tvModuleStatus.text = "Module status: install via LSPosed"
    }

    private fun refreshSelectedApps() {
        CoroutineScope(Dispatchers.IO).launch {
            val enabled = ConfigWriter.getEnabledApps(this@MainActivity)
            val pm = packageManager
            val chips = enabled.map { pkg ->
                val label = try {
                    pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
                } catch (_: PackageManager.NameNotFoundException) { pkg }
                Pair(pkg, label)
            }.sortedBy { it.second }

            withContext(Dispatchers.Main) {
                b.chipGroupSelectedApps.removeAllViews()
                if (chips.isEmpty()) {
                    b.tvSelectedAppsLabel.visibility = View.VISIBLE
                } else {
                    b.tvSelectedAppsLabel.visibility = View.GONE
                    chips.forEach { (pkg, label) ->
                        val chip = Chip(this@MainActivity).apply {
                            text = label
                            isCloseIconVisible = true
                            isClickable = true
                            isCheckable = false
                            setOnLongClickListener {
                                Toast.makeText(this@MainActivity, pkg, Toast.LENGTH_SHORT).show()
                                true
                            }
                            setOnCloseIconClickListener {
                                ConfigWriter.setAppEnabled(this@MainActivity, pkg, false)
                                refreshSelectedApps()
                            }
                        }
                        b.chipGroupSelectedApps.addView(chip)
                    }
                }
            }
        }
    }

    private fun setupListeners() {
        b.btnSelectApps.setOnClickListener {
            startActivity(Intent(this, AppListActivity::class.java))
        }

        b.btnApplyIptables.setOnClickListener {
            applyIptables()
        }

        b.btnFlushIptables.setOnClickListener {
            val host = b.etProxyHost.text.toString().trim()
            val port = b.etProxyPort.text.toString().toIntOrNull() ?: 8080
            IptablesManager.removeGlobalRedirect(host, port)
            IptablesManager.removeAllRules()
                .onSuccess { toast("iptables rules flushed") }
                .onFailure { toast("Flush failed: ${it.message}") }
        }

        b.btnViewRules.setOnClickListener {
            startActivity(Intent(this, ActiveRulesActivity::class.java))
        }

        b.switchProxy.setOnCheckedChangeListener { _, _ -> saveProxyConfig() }

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

        IptablesManager.applyGlobalRedirect(host, port)
            .onFailure { toast("Global redirect failed: ${it.message}") }

        val enabledApps = ConfigWriter.getEnabledApps(this)
        if (enabledApps.isEmpty()) {
            toast("Global redirect applied")
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
        toast("Global redirect + $applied app rules applied, $failed failed")
    }

    private fun saveProxyConfig() {
        val host = b.etProxyHost.text.toString().trim()
        val port = b.etProxyPort.text.toString().toIntOrNull() ?: 8080
        ConfigWriter.setProxyConfig(this, host, port, b.switchProxy.isChecked)
    }

    private fun toast(msg: String) =
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
}
