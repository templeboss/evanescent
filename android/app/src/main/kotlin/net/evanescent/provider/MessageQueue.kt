package net.evanescent.provider

import kotlinx.coroutines.CompletableDeferred
import java.util.concurrent.ConcurrentHashMap

/**
 * Tracks outbound SendMessage and GetPreKeys frames waiting for server acknowledgement.
 * Completed with (ok, errorCode) so callers can distinguish failure reasons.
 */
class MessageQueue {
    private val pending = ConcurrentHashMap<String, CompletableDeferred<Pair<Boolean, String>>>()
    private val bundles = ConcurrentHashMap<String, ByteArray>()

    /** Register a pending send and return its deferred result. */
    fun register(correlationId: String): CompletableDeferred<Pair<Boolean, String>> {
        val deferred = CompletableDeferred<Pair<Boolean, String>>()
        pending[correlationId] = deferred
        return deferred
    }

    /** Complete the pending send with success/failure and optional error code. */
    fun complete(correlationId: String, ok: Boolean, errorCode: String = "") {
        pending.remove(correlationId)?.complete(Pair(ok, errorCode))
    }

    /**
     * Complete a GetPreKeys request with the received bundle bytes.
     * Signals success (true) so the awaiting coroutine can call [takePreKeyBundle].
     */
    fun completeWithBundle(correlationId: String, bundle: ByteArray) {
        bundles[correlationId] = bundle
        pending.remove(correlationId)?.complete(Pair(true, ""))
    }

    /**
     * Retrieve and remove the PreKeyBundle bytes stored for a GetPreKeys correlation ID.
     * Returns null if not found (e.g., already consumed or wrong ID).
     */
    fun takePreKeyBundle(correlationId: String): ByteArray? = bundles.remove(correlationId)

    /** Cancel all pending sends (e.g., on disconnect). */
    fun cancelAll() {
        pending.values.forEach { it.cancel() }
        pending.clear()
        bundles.clear()
    }
}
