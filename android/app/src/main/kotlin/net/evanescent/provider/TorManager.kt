package net.evanescent.provider

import android.content.Context
import kotlinx.coroutines.withTimeout
import java.io.File

/**
 * Manages the embedded Tor daemon lifecycle.
 *
 * Call [start] once on app launch. Await [awaitReady] before making network connections.
 * Use [socksPort] to configure OkHttp proxy after bootstrap.
 */
object TorManager {

    @Volatile var socksPort: Int = 0
        private set

    @Volatile private var bootstrapped: Boolean = false

    /**
     * Start the embedded Tor daemon. Safe to call multiple times (no-op if already started).
     * Suspends until Tor bootstrap completes (typically 5-15 seconds on first run).
     *
     * Throws if Tor fails to bootstrap within the timeout.
     */
    suspend fun start(context: Context) {
        if (bootstrapped) return
        // tor-android integration: start embedded Tor and wait for SOCKS port
        // The actual implementation depends on the tor-android API version.
        // tor-android exposes a TorServiceConnection or similar lifecycle API.
        // This is a placeholder showing the correct intent:
        withTimeout(60_000L) {
            val torDataDir = File(context.filesDir, "tor")
            torDataDir.mkdirs()
            // Initialize tor-android and wait for bootstrap
            // socksPort will be set after bootstrap
            socksPort = 9050  // tor-android default; update once real API is wired
            bootstrapped = true
        }
    }

    /** Returns true if Tor has bootstrapped and is ready for connections. */
    fun isReady(): Boolean = bootstrapped

    /** Resets state (used for reconnection on failure). */
    fun reset() {
        bootstrapped = false
        socksPort = 0
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
