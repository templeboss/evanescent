package net.evanescent.provider

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager

/**
 * Helpers for checking and starting Orbot.
 * All network connections route through Orbot's SOCKS5 proxy (127.0.0.1:9050).
 * Never falls back to direct connections.
 */
object OrbotHelper {

    private const val ORBOT_PACKAGE = "org.torproject.android"
    const val SOCKS5_HOST = "127.0.0.1"
    const val SOCKS5_PORT = 9050

    fun isOrbotInstalled(context: Context): Boolean = try {
        context.packageManager.getPackageInfo(ORBOT_PACKAGE, 0)
        true
    } catch (e: PackageManager.NameNotFoundException) {
        false
    }

    fun requestOrbotStart(context: Context) {
        val intent = Intent("org.torproject.android.intent.action.REQUEST_START")
        intent.setPackage(ORBOT_PACKAGE)
        context.startForegroundService(intent)
    }

    /**
     * Validates a v3 .onion address.
     * Must be exactly 56 base32 characters + ".onion" = 62 characters total.
     */
    fun isValidOnionAddress(address: String): Boolean {
        if (address.length != 62) return false
        if (!address.endsWith(".onion")) return false
        val host = address.dropLast(6)
        return host.all { it in 'a'..'z' || it in '2'..'7' }
    }
}
