package com.horizon.sslkillswitch.iptables

import android.content.Context
import android.content.pm.PackageManager

data class IptablesRule(
    val uid: Int,
    val packageName: String,
    val proxyHost: String,
    val proxyPort: Int
)

object IptablesManager {

    private val activeRules = mutableListOf<IptablesRule>()

    fun applyRule(rule: IptablesRule): Result<Unit> = runCatching {
        val dest = "${rule.proxyHost}:${rule.proxyPort}"
        exec("iptables -t nat -A OUTPUT -m owner --uid-owner ${rule.uid} -p tcp -j DNAT --to-destination $dest")
        exec("ip6tables -t nat -A OUTPUT -m owner --uid-owner ${rule.uid} -p tcp -j DNAT --to-destination $dest")
        synchronized(activeRules) { activeRules.add(rule) }
    }

    fun removeRule(rule: IptablesRule): Result<Unit> = runCatching {
        val dest = "${rule.proxyHost}:${rule.proxyPort}"
        exec("iptables -t nat -D OUTPUT -m owner --uid-owner ${rule.uid} -p tcp -j DNAT --to-destination $dest")
        exec("ip6tables -t nat -D OUTPUT -m owner --uid-owner ${rule.uid} -p tcp -j DNAT --to-destination $dest")
        synchronized(activeRules) { activeRules.remove(rule) }
    }

    fun applyGlobalRedirect(destHost: String): Result<Unit> = runCatching {
        exec("iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination $destHost:443")
        exec("iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination $destHost:80")
        exec("iptables -t nat -A POSTROUTING -p tcp --dport 443 -j MASQUERADE")
        exec("iptables -t nat -A POSTROUTING -p tcp --dport 80 -j MASQUERADE")
    }

    fun removeGlobalRedirect(destHost: String): Result<Unit> = runCatching {
        exec("iptables -t nat -D OUTPUT -p tcp --dport 443 -j DNAT --to-destination $destHost:443")
        exec("iptables -t nat -D OUTPUT -p tcp --dport 80 -j DNAT --to-destination $destHost:80")
        exec("iptables -t nat -D POSTROUTING -p tcp --dport 443 -j MASQUERADE")
        exec("iptables -t nat -D POSTROUTING -p tcp --dport 80 -j MASQUERADE")
    }

    fun removeAllRules(): Result<Unit> = runCatching {
        synchronized(activeRules) {
            activeRules.toList().forEach { rule ->
                removeRule(rule).getOrNull()
            }
            activeRules.clear()
        }
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
        if (exitCode != 0) {
            val err = proc.errorStream.bufferedReader().readText()
            throw RuntimeException("Command '$cmd' failed (exit $exitCode): $err")
        }
    }
}
