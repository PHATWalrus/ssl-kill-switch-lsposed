package com.horizon.sslkillswitch.ui

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.horizon.sslkillswitch.databinding.ActivityActiveRulesBinding
import com.horizon.sslkillswitch.databinding.ItemIptablesRuleBinding
import com.horizon.sslkillswitch.iptables.IptablesManager
import com.horizon.sslkillswitch.iptables.IptablesRule
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private data class RuleItem(
    val label: String,
    val proxyInfo: String,
    val subInfo: String,
    val onDelete: () -> Unit
)

class ActiveRulesActivity : AppCompatActivity() {

    private lateinit var b: ActivityActiveRulesBinding
    private val adapter = RulesAdapter()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        b = ActivityActiveRulesBinding.inflate(layoutInflater)
        setContentView(b.root)

        b.rvRules.layoutManager = LinearLayoutManager(this)
        b.rvRules.adapter = adapter

        b.btnFlushAll.setOnClickListener { confirmFlushAll() }
        b.btnRefreshDump.setOnClickListener { loadNatDump() }
    }

    override fun onResume() {
        super.onResume()
        refreshRules()
        loadNatDump()
    }

    private fun refreshRules() {
        val items = mutableListOf<RuleItem>()

        // Global redirect row
        IptablesManager.getGlobalRedirect()?.let { (host, port) ->
            items += RuleItem(
                label     = "Global Redirect",
                proxyInfo = "→ $host:$port",
                subInfo   = "all TCP 80/443",
                onDelete  = {
                    confirmDelete("Global Redirect", host, port) {
                        CoroutineScope(Dispatchers.IO).launch {
                            IptablesManager.removeGlobalRedirect(host, port)
                            withContext(Dispatchers.Main) { refreshRules(); loadNatDump(); toast("Global redirect removed") }
                        }
                    }
                }
            )
        }

        // Per-app rules
        IptablesManager.getActiveRules().forEach { rule ->
            items += RuleItem(
                label     = rule.packageName,
                proxyInfo = "→ ${rule.proxyHost}:${rule.proxyPort}",
                subInfo   = "uid ${rule.uid}",
                onDelete  = { confirmDeleteRule(rule) }
            )
        }

        adapter.submitList(items)
        b.rvRules.visibility    = if (items.isEmpty()) View.GONE else View.VISIBLE
        b.tvEmptyRules.visibility = if (items.isEmpty()) View.VISIBLE else View.GONE
    }

    private fun confirmDelete(label: String, host: String, port: Int, onConfirm: () -> Unit) {
        AlertDialog.Builder(this)
            .setTitle("Delete rule")
            .setMessage("Remove $label → $host:$port?")
            .setPositiveButton("Delete") { _, _ -> onConfirm() }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun confirmDeleteRule(rule: IptablesRule) {
        confirmDelete(rule.packageName, rule.proxyHost, rule.proxyPort) {
            CoroutineScope(Dispatchers.IO).launch {
                val result = IptablesManager.removeRule(rule)
                withContext(Dispatchers.Main) {
                    result
                        .onSuccess { refreshRules(); loadNatDump(); toast("Rule removed") }
                        .onFailure { toast("Failed: ${it.message}") }
                }
            }
        }
    }

    private fun confirmFlushAll() {
        AlertDialog.Builder(this)
            .setTitle("Flush all rules")
            .setMessage("This clears the entire iptables NAT OUTPUT chain. Continue?")
            .setPositiveButton("Flush") { _, _ ->
                CoroutineScope(Dispatchers.IO).launch {
                    val result = IptablesManager.flushAll()
                    withContext(Dispatchers.Main) {
                        result
                            .onSuccess { refreshRules(); b.tvNatDump.text = "— flushed —"; toast("All rules flushed") }
                            .onFailure { toast("Flush failed: ${it.message}") }
                    }
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
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

private class RulesAdapter : RecyclerView.Adapter<RulesAdapter.VH>() {

    private val items = mutableListOf<RuleItem>()

    fun submitList(list: List<RuleItem>) {
        items.clear(); items.addAll(list); notifyDataSetChanged()
    }

    inner class VH(val b: ItemIptablesRuleBinding) : RecyclerView.ViewHolder(b.root)

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) =
        VH(ItemIptablesRuleBinding.inflate(LayoutInflater.from(parent.context), parent, false))

    override fun getItemCount() = items.size

    override fun onBindViewHolder(holder: VH, position: Int) {
        val item = items[position]
        with(holder.b) {
            tvRulePackage.text = item.label
            tvRuleProxy.text   = item.proxyInfo
            tvRuleUid.text     = item.subInfo
            btnDeleteRule.setOnClickListener { item.onDelete() }
        }
    }
}
