package com.horizon.sslkillswitch.ui

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.horizon.sslkillswitch.config.ConfigWriter
import com.horizon.sslkillswitch.databinding.ActivityAppListBinding
import com.horizon.sslkillswitch.databinding.ItemAppBinding
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class AppListActivity : AppCompatActivity() {

    private lateinit var b: ActivityAppListBinding
    private val adapter = AppAdapter()
    private val allApps = mutableListOf<AppInfo>()

    data class AppInfo(
        val packageName: String,
        val label: String,
        var enabled: Boolean,
        var domains: String
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        b = ActivityAppListBinding.inflate(layoutInflater)
        setContentView(b.root)

        b.recyclerView.layoutManager = LinearLayoutManager(this)
        b.recyclerView.adapter = adapter

        b.etSearch.addTextChangedListener(object : TextWatcher {
            override fun afterTextChanged(s: Editable?) = filterApps(s.toString())
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
        })

        loadApps()
    }

    private fun loadApps() {
        CoroutineScope(Dispatchers.IO).launch {
            val pm = packageManager
            val packages = pm.getInstalledApplications(PackageManager.GET_META_DATA)
                .filter { (it.flags and ApplicationInfo.FLAG_SYSTEM) == 0 } // user apps only
                .sortedBy { pm.getApplicationLabel(it).toString() }

            val enabledApps = ConfigWriter.getEnabledApps(this@AppListActivity)

            val apps = packages.map { info ->
                val pkg = info.packageName
                AppInfo(
                    packageName = pkg,
                    label = pm.getApplicationLabel(info).toString(),
                    enabled = enabledApps.contains(pkg),
                    domains = ConfigWriter.getDomainsForApp(this@AppListActivity, pkg)
                        .joinToString(",")
                )
            }

            withContext(Dispatchers.Main) {
                allApps.clear()
                allApps.addAll(apps)
                adapter.submitList(apps.toList())
            }
        }
    }

    private fun filterApps(query: String) {
        val filtered = if (query.isEmpty()) {
            allApps.toList()
        } else {
            allApps.filter {
                it.label.contains(query, ignoreCase = true) ||
                    it.packageName.contains(query, ignoreCase = true)
            }
        }
        adapter.submitList(filtered)
    }

    inner class AppAdapter : RecyclerView.Adapter<AppAdapter.VH>() {
        private val items = mutableListOf<AppInfo>()

        fun submitList(list: List<AppInfo>) {
            items.clear()
            items.addAll(list)
            notifyDataSetChanged()
        }

        inner class VH(val b: ItemAppBinding) : RecyclerView.ViewHolder(b.root)

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH =
            VH(ItemAppBinding.inflate(LayoutInflater.from(parent.context), parent, false))

        override fun getItemCount() = items.size

        override fun onBindViewHolder(holder: VH, position: Int) {
            val app = items[position]
            with(holder.b) {
                tvAppName.text = app.label
                tvPackageName.text = app.packageName
                switchEnabled.isChecked = app.enabled

                switchEnabled.setOnCheckedChangeListener { _, checked ->
                    app.enabled = checked
                    ConfigWriter.setAppEnabled(this@AppListActivity, app.packageName, checked)
                }

                btnEditDomains.setOnClickListener {
                    showDomainDialog(app)
                }
            }
        }

        private fun showDomainDialog(app: AppInfo) {
            val current = ConfigWriter.getDomainsForApp(
                this@AppListActivity, app.packageName
            ).joinToString("\n")

            val input = android.widget.EditText(this@AppListActivity).apply {
                hint = "One domain per line (empty = all)"
                setText(current)
                setPadding(48, 16, 48, 16)
            }

            AlertDialog.Builder(this@AppListActivity)
                .setTitle("Domain filter — ${app.label}")
                .setMessage("Leave empty to bypass all domains.\nEnter suffixes like: example.com")
                .setView(input)
                .setPositiveButton("Save") { _, _ ->
                    val domains = input.text.toString()
                        .lines()
                        .map { it.trim() }
                        .filter { it.isNotEmpty() }
                        .toSet()
                    ConfigWriter.setDomainsForApp(this@AppListActivity, app.packageName, domains)
                    app.domains = domains.joinToString(",")
                }
                .setNegativeButton("Cancel", null)
                .show()
        }
    }
}
