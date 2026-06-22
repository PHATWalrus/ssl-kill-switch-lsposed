package com.horizon.sslkillswitch.iptables

import android.content.Context
import android.content.pm.PackageManager
import android.util.Log

data class IptablesRule(
    val uid: Int,
    val packageName: String,
    val proxyHost: String,
    val proxyPort: Int
)

object IptablesManager {

    private val activeRules = mutableListOf<IptablesRule>()
    @Volatile private var globalRedirect: Pair<String, Int>? = null
    private const val TAG = "IptablesManager"

    fun applyRule(rule: IptablesRule): Result<Unit> = runCatching {
        val dest = "${rule.proxyHost}:${rule.proxyPort}"
        exec("iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination $dest")
        exec("iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination $dest")
        exec("iptables -t nat -A POSTROUTING -p tcp --dport 443 -j MASQUERADE")
        exec("iptables -t nat -A POSTROUTING -p tcp --dport 80 -j MASQUERADE")
        synchronized(activeRules) { activeRules.add(rule) }
    }

    fun removeRule(rule: IptablesRule): Result<Unit> = runCatching {
        val dest = "${rule.proxyHost}:${rule.proxyPort}"
        exec("iptables -t nat -D OUTPUT -p tcp --dport 443 -j DNAT --to-destination $dest")
        exec("iptables -t nat -D OUTPUT -p tcp --dport 80 -j DNAT --to-destination $dest")
        exec("iptables -t nat -D POSTROUTING -p tcp --dport 443 -j MASQUERADE")
        exec("iptables -t nat -D POSTROUTING -p tcp --dport 80 -j MASQUERADE")
        synchronized(activeRules) { activeRules.remove(rule) }
    }

    // Redirect all TCP 80/443 to proxy. Excludes traffic already destined for proxy to avoid loop.
    fun applyGlobalRedirect(destHost: String, destPort: Int): Result<Unit> = runCatching {
        exec("iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination $destHost:$destPort")
        exec("iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination $destHost:$destPort")
        exec("iptables -t nat -A POSTROUTING -p tcp --dport 443 -j MASQUERADE")
        exec("iptables -t nat -A POSTROUTING -p tcp --dport 80 -j MASQUERADE")
        globalRedirect = Pair(destHost, destPort)
    }

    fun removeGlobalRedirect(destHost: String, destPort: Int): Result<Unit> = runCatching {
        exec("iptables -t nat -D OUTPUT -p tcp --dport 443 -j DNAT --to-destination $destHost:$destPort")
        exec("iptables -t nat -D OUTPUT -p tcp --dport 80 -j DNAT --to-destination $destHost:$destPort")
        globalRedirect = null
    }

    fun getGlobalRedirect(): Pair<String, Int>? = globalRedirect

    fun removeAllRules(): Result<Unit> = runCatching {
        synchronized(activeRules) {
            activeRules.toList().forEach { removeRule(it).getOrNull() }
            activeRules.clear()
        }
    }

    fun flushAll(): Result<Unit> = runCatching {
        exec("iptables -t nat -F OUTPUT")
        synchronized(activeRules) { activeRules.clear() }
        globalRedirect = null
    }

    fun getActiveRules(): List<IptablesRule> = synchronized(activeRules) { activeRules.toList() }

    fun getAppUid(context: Context, packageName: String): Int? = try {
        context.packageManager.getApplicationInfo(packageName, 0).uid
    } catch (_: PackageManager.NameNotFoundException) { null }

    fun dumpNatTable(): String = try {
        val proc = Runtime.getRuntime().exec(arrayOf("su", "-c", "iptables -t nat -L OUTPUT -n --line-numbers"))
        proc.inputStream.bufferedReader().readText()
    } catch (e: Exception) {
        "Error: ${e.message}"
    }

    private fun exec(cmd: String) {
        val proc = Runtime.getRuntime().exec(arrayOf("su", "-c", cmd))
        val exitCode = proc.waitFor()
        Log.d(TAG,"$cmd exit code: $exitCode")
        if (exitCode != 0) {
            val err = proc.errorStream.bufferedReader().readText()
            throw RuntimeException("Command '$cmd' failed (exit $exitCode): $err")
        }
    }
}
