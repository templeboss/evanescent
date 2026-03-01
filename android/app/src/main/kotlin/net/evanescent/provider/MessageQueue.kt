package net.evanescent.provider

import kotlinx.coroutines.CompletableDeferred
import java.util.concurrent.ConcurrentHashMap

/**
 * Tracks outbound SendMessage frames waiting for SendAck.
 * Completed with (ok, errorCode) so callers can distinguish failure reasons.
 */
class MessageQueue {
    private val pending = ConcurrentHashMap<String, CompletableDeferred<Pair<Boolean, String>>>()

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

    /** Cancel all pending sends (e.g., on disconnect). */
    fun cancelAll() {
        pending.values.forEach { it.cancel() }
        pending.clear()
    }
}
