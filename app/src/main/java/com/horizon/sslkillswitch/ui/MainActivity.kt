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
        b.switchLogging.isChecked = ConfigWriter.isLoggingEnabled(this)
        showModuleStatus()
    }

    private fun showModuleStatus() {
        val active = com.horizon.sslkillswitch.status.ModuleStatus.isActive()
        val green = 0xFF4CAF50.toInt()
        val red   = 0xFFE53935.toInt()
        if (active) {
            b.tvModuleStatus.text = "✓ Active — hooks loaded in this process"
            b.tvModuleStatus.setTextColor(green)
            b.tvFrameworkInfo.text = "LSPosed/Xposed API v${com.horizon.sslkillswitch.status.ModuleStatus.frameworkVersion()}"
            b.tvFrameworkInfo.visibility = View.VISIBLE
        } else {
            b.tvModuleStatus.text = "✗ Inactive — enable the module in LSPosed and add this app to its scope"
            b.tvModuleStatus.setTextColor(red)
            b.tvFrameworkInfo.visibility = View.GONE
        }
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
                .onSuccess {
                    toast("iptables rules flushed")
                    refreshIptablesDisplay()
                }
                .onFailure { toast("Flush failed: ${it.message}") }
        }

        b.btnViewRules.setOnClickListener {
            startActivity(Intent(this, ActiveRulesActivity::class.java))
        }

        b.btnViewLogs.setOnClickListener {
            startActivity(Intent(this, LogViewerActivity::class.java))
        }

        b.switchProxy.setOnCheckedChangeListener { _, _ -> saveProxyConfig() }

        b.switchLogging.setOnCheckedChangeListener { _, checked ->
            ConfigWriter.setLoggingEnabled(this, checked)
        }

        // Scroll proxy card into view when keyboard opens.
        // OnGlobalLayoutListener fires after every layout pass — including the resize
        // triggered by the soft keyboard — so cardProxy.top is always the post-keyboard value.
        b.scrollView.viewTreeObserver.addOnGlobalLayoutListener {
            if (currentFocus == b.etProxyHost || currentFocus == b.etProxyPort) {
                b.scrollView.smoothScrollTo(0, b.cardProxy.top)
            }
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
            refreshIptablesDisplay()
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
        refreshIptablesDisplay()
    }

    private fun refreshIptablesDisplay() {
        CoroutineScope(Dispatchers.IO).launch {
            val dump = IptablesManager.dumpNatTable()
            withContext(Dispatchers.Main) {
                val text = dump.trim().ifBlank { "No rules active" }
                b.tvIptablesRulesInline.text = text
                b.tvIptablesRulesInline.visibility = View.VISIBLE
            }
        }
    }

    private fun saveProxyConfig() {
        val host = b.etProxyHost.text.toString().trim()
        val port = b.etProxyPort.text.toString().toIntOrNull() ?: 8080
        ConfigWriter.setProxyConfig(this, host, port, b.switchProxy.isChecked)
    }

    private fun toast(msg: String) =
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
}
