package com.horizon.sslkillswitch.ui

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.chip.Chip
import com.google.android.material.chip.ChipGroup
import com.horizon.sslkillswitch.config.ConfigWriter
import com.horizon.sslkillswitch.config.FLUTTER_MODE_KOTLIN
import com.horizon.sslkillswitch.config.FLUTTER_MODE_NATIVE
import com.horizon.sslkillswitch.config.KEY_HOOK_NATIVE
import com.horizon.sslkillswitch.config.KEY_HOOK_OKHTTP
import com.horizon.sslkillswitch.config.KEY_HOOK_TRUSTMANAGER
import com.horizon.sslkillswitch.config.KEY_HOOK_WEBVIEW
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
    private var showSelectedOnly = false

    data class AppInfo(
        val isSystem: Boolean,
        val packageName: String,
        val label: String,
        var enabled: Boolean,
        var hookTm: Boolean,
        var hookOkHttp: Boolean,
        var hookWebView: Boolean,
        var hookNative: Boolean,
        var flutterMode: String,
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

        b.chipSelectedOnly.setOnCheckedChangeListener { _, checked ->
            showSelectedOnly = checked
            filterApps(b.etSearch.text.toString())
        }

        loadApps()
    }

    private fun loadApps() {
        CoroutineScope(Dispatchers.IO).launch {
            val pm = packageManager
            val packages = pm.getInstalledApplications(PackageManager.GET_META_DATA)
                                .sortedBy { pm.getApplicationLabel(it).toString() }

            val enabledApps = ConfigWriter.getEnabledApps(this@AppListActivity)
            val tmApps      = ConfigWriter.getHookCategoryApps(this@AppListActivity, KEY_HOOK_TRUSTMANAGER)
            val okhttpApps  = ConfigWriter.getHookCategoryApps(this@AppListActivity, KEY_HOOK_OKHTTP)
            val webviewApps = ConfigWriter.getHookCategoryApps(this@AppListActivity, KEY_HOOK_WEBVIEW)
            val nativeApps  = ConfigWriter.getHookCategoryApps(this@AppListActivity, KEY_HOOK_NATIVE)

            val apps = packages.map { info ->
                val pkg = info.packageName
                AppInfo(
                    isSystem     = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
                    packageName  = pkg,
                    label        = pm.getApplicationLabel(info).toString(),
                    enabled      = enabledApps.contains(pkg),
                    hookTm       = tmApps.contains(pkg),
                    hookOkHttp   = okhttpApps.contains(pkg),
                    hookWebView  = webviewApps.contains(pkg),
                    hookNative   = nativeApps.contains(pkg),
                    flutterMode  = ConfigWriter.getFlutterMode(this@AppListActivity, pkg),
                    domains      = ConfigWriter.getDomainsForApp(this@AppListActivity, pkg).joinToString(",")
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
        val filtered = allApps.filter {
            val matchesSearch = query.isEmpty() ||
                it.label.contains(query, ignoreCase = true) ||
                it.packageName.contains(query, ignoreCase = true)
            val matchesFilter = !showSelectedOnly || it.enabled
            matchesSearch && matchesFilter
        }
        adapter.submitList(filtered)
    }

    inner class AppAdapter : RecyclerView.Adapter<AppAdapter.VH>() {
        private val items = mutableListOf<AppInfo>()

        fun submitList(list: List<AppInfo>) {
            items.clear(); items.addAll(list); notifyDataSetChanged()
        }

        inner class VH(val b: ItemAppBinding) : RecyclerView.ViewHolder(b.root)

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH =
            VH(ItemAppBinding.inflate(LayoutInflater.from(parent.context), parent, false))

        override fun getItemCount() = items.size

        override fun onBindViewHolder(holder: VH, position: Int) {
            val app = items[position]
            with(holder.b) {
                if (app.isSystem) {
                    tvSystemBadge.visibility = View.VISIBLE
                } else {
                    tvSystemBadge.visibility = View.GONE
                }
                tvAppName.text     = app.label
                tvPackageName.text = app.packageName

                // Clear all listeners before setting state
                switchEnabled.setOnCheckedChangeListener(null)
                chipTrustManager.setOnCheckedChangeListener(null)
                chipOkHttp.setOnCheckedChangeListener(null)
                chipWebView.setOnCheckedChangeListener(null)
                chipNative.setOnCheckedChangeListener(null)
                chipFlutterNative.setOnCheckedChangeListener(null)
                chipFlutterKotlin.setOnCheckedChangeListener(null)

                switchEnabled.isChecked    = app.enabled
                chipTrustManager.isChecked = app.hookTm
                chipOkHttp.isChecked       = app.hookOkHttp
                chipWebView.isChecked      = app.hookWebView
                chipNative.isChecked       = app.hookNative

                chipFlutterNative.isChecked = app.flutterMode == FLUTTER_MODE_NATIVE
                chipFlutterKotlin.isChecked = app.flutterMode == FLUTTER_MODE_KOTLIN

                layoutOptions.visibility     = if (app.enabled) View.VISIBLE else View.GONE
                layoutFlutterMode.visibility = if (app.enabled && app.hookNative) View.VISIBLE else View.GONE

                switchEnabled.setOnCheckedChangeListener { _, checked ->
                    app.enabled = checked
                    ConfigWriter.setAppEnabled(this@AppListActivity, app.packageName, checked)
                    layoutOptions.visibility = if (checked) View.VISIBLE else View.GONE
                    if (checked) {
                        chipTrustManager.isChecked = true
                        chipOkHttp.isChecked       = true
                        chipWebView.isChecked       = true
                        chipNative.isChecked        = true
                        app.hookTm      = true; app.hookOkHttp  = true
                        app.hookWebView = true; app.hookNative  = true
                        layoutFlutterMode.visibility = View.VISIBLE
                    } else {
                        layoutFlutterMode.visibility = View.GONE
                    }
                    if (showSelectedOnly) filterApps(b.etSearch.text.toString())
                }

                chipTrustManager.setOnCheckedChangeListener { _, checked ->
                    app.hookTm = checked
                    ConfigWriter.setHookCategory(this@AppListActivity, KEY_HOOK_TRUSTMANAGER, app.packageName, checked)
                }
                chipOkHttp.setOnCheckedChangeListener { _, checked ->
                    app.hookOkHttp = checked
                    ConfigWriter.setHookCategory(this@AppListActivity, KEY_HOOK_OKHTTP, app.packageName, checked)
                }
                chipWebView.setOnCheckedChangeListener { _, checked ->
                    app.hookWebView = checked
                    ConfigWriter.setHookCategory(this@AppListActivity, KEY_HOOK_WEBVIEW, app.packageName, checked)
                }
                chipNative.setOnCheckedChangeListener { _, checked ->
                    app.hookNative = checked
                    ConfigWriter.setHookCategory(this@AppListActivity, KEY_HOOK_NATIVE, app.packageName, checked)
                    layoutFlutterMode.visibility = if (checked) View.VISIBLE else View.GONE
                }

                chipFlutterNative.setOnCheckedChangeListener { _, checked ->
                    if (checked) {
                        app.flutterMode = FLUTTER_MODE_NATIVE
                        ConfigWriter.setFlutterMode(this@AppListActivity, app.packageName, FLUTTER_MODE_NATIVE)
                    }
                }
                chipFlutterKotlin.setOnCheckedChangeListener { _, checked ->
                    if (checked) {
                        app.flutterMode = FLUTTER_MODE_KOTLIN
                        ConfigWriter.setFlutterMode(this@AppListActivity, app.packageName, FLUTTER_MODE_KOTLIN)
                    }
                }

                btnEditDomains.setOnClickListener { showDomainDialog(app) }
            }
        }

        private fun showDomainDialog(app: AppInfo) {
            val ctx = this@AppListActivity
            val domains = ConfigWriter.getDomainsForApp(ctx, app.packageName).toMutableSet()

            val chipGroup = ChipGroup(ctx)
            fun syncChips() {
                chipGroup.removeAllViews()
                for (d in domains.sorted()) {
                    chipGroup.addView(Chip(ctx).apply {
                        text = d; isCloseIconVisible = true
                        setOnCloseIconClickListener { domains.remove(d); syncChips() }
                    })
                }
            }
            syncChips()

            val input  = EditText(ctx).apply { hint = "example.com" }
            val btnAdd = Button(ctx).apply { text = "Add" }
            btnAdd.setOnClickListener {
                val d = input.text.toString().trim().lowercase()
                if (d.isNotEmpty()) { domains.add(d); input.setText(""); syncChips() }
            }

            val inputRow = LinearLayout(ctx).apply {
                orientation = LinearLayout.HORIZONTAL
                addView(input, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
                addView(btnAdd)
            }
            val layout = LinearLayout(ctx).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(48, 16, 48, 8)
                addView(chipGroup); addView(inputRow)
            }

            AlertDialog.Builder(ctx)
                .setTitle("Domains — ${app.label}")
                .setMessage("Leave empty to bypass all. Suffix match: example.com")
                .setView(layout)
                .setPositiveButton("Save") { _, _ ->
                    ConfigWriter.setDomainsForApp(ctx, app.packageName, domains)
                    app.domains = domains.joinToString(",")
                }
                .setNegativeButton("Cancel", null)
                .show()
        }
    }
}
