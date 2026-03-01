package net.evanescent.provider

import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import net.evanescent.crypto.Hkdf
import okhttp3.*
import okio.ByteString.Companion.toByteString
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import java.net.InetSocketAddress
import java.net.Proxy
import java.util.UUID
import java.util.concurrent.TimeUnit

private const val TAG = "Evanescent"

/**
 * WebSocket client for the Personal Provider.
 * All connections route through Orbot SOCKS5 proxy.
 * Handles: authentication, FetchMessages polling, SendMessage with ack.
 */
class ProviderClient(
    private val identityPriv: ByteArray,
    private val identityPub: ByteArray,
    private val onEnvelopeReceived: suspend (id: String, envelope: ByteArray) -> Unit,
    private val onProviderInfo: (nymAddress: String, onionAddress: String) -> Unit = { _, _ -> },
    private val onAuthenticated: suspend (ws: WebSocket) -> Unit = {}
) {
    private val queue = MessageQueue()
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private val _connectionState = MutableSharedFlow<ConnectionState>(replay = 1)
    val connectionState: SharedFlow<ConnectionState> = _connectionState

    @Volatile private var socket: WebSocket? = null
    @Volatile private var authed = false
    @Volatile private var pendingNonce: ByteArray? = null
    @Volatile private var pendingAckIds: MutableList<String> = mutableListOf()

    private val client: OkHttpClient = OkHttpClient.Builder()
        .proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress(OrbotHelper.SOCKS5_HOST, OrbotHelper.SOCKS5_PORT)))
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(60, TimeUnit.SECONDS)
        .build()

    sealed class ConnectionState {
        object Disconnected : ConnectionState()
        object Connecting : ConnectionState()
        object Authenticating : ConnectionState()
        object Connected : ConnectionState()
    }

    fun connect(onionAddress: String) {
        require(OrbotHelper.isValidOnionAddress(onionAddress)) { "Invalid .onion address: $onionAddress" }
        scope.launch { connectWithBackoff(onionAddress) }
    }

    private suspend fun connectWithBackoff(onionAddress: String) {
        val backoffMs = longArrayOf(5_000, 10_000, 20_000, 40_000, 120_000)
        var attempt = 0
        while (isActive) {
            _connectionState.emit(ConnectionState.Connecting)
            try {
                connectOnce(onionAddress)
            } catch (e: Exception) {
                Log.w(TAG, "connection failed: ${e.message}")
            }
            val delay = backoffMs[minOf(attempt++, backoffMs.size - 1)]
            delay(delay)
        }
    }

    private suspend fun connectOnce(onionAddress: String) {
        val url = "ws://$onionAddress/ws"
        val request = Request.Builder().url(url).build()
        val listener = WsListener()
        val ws = client.newWebSocket(request, listener)
        socket = ws
        listener.awaitClose()
    }

    /**
     * Send a sealed envelope to the provider.
     * @return null on success, or the error code string on failure (e.g. "PREKEY_EXHAUSTED").
     */
    suspend fun send(toNymAddress: String, sealedEnvelope: ByteArray): String? {
        val correlationId = UUID.randomUUID().toString()
        val deferred = queue.register(correlationId)
        val msg = buildSendMessage(correlationId, toNymAddress, sealedEnvelope)
        if (socket?.send(msg.toByteString()) != true) return "NO_SOCKET"
        return try {
            val (ok, errorCode) = withTimeout(30_000) { deferred.await() }
            if (ok) null else errorCode.ifEmpty { "SEND_FAILED" }
        } catch (e: TimeoutCancellationException) {
            queue.complete(correlationId, false, "TIMEOUT")
            "TIMEOUT"
        }
    }

    fun disconnect() {
        scope.cancel()
        socket?.close(1000, "shutdown")
        queue.cancelAll()
    }

    /** Send a pre-built proto frame to the provider. Returns false if not connected. */
    fun sendFrame(frameBytes: ByteArray): Boolean {
        return socket?.send(frameBytes.toByteString()) ?: false
    }

    /** Build an UploadPreKeys WsClientMessage frame from raw PreKeyEntity fields. */
    fun buildUploadPreKeysFrame(
        signedPreKeys: List<Triple<Int, ByteArray, ByteArray>>,   // (id, publicKey, signature)
        oneTimePreKeys: List<Pair<Int, ByteArray>>                 // (id, publicKey)
    ): ByteArray {
        // UploadPreKeys inner payload: field 1 = repeated SignedPreKey, field 2 = repeated OneTimePreKey.
        var uploadPayload = byteArrayOf()
        for ((id, pub, sig) in signedPreKeys) {
            val spkMsg = encodeTag(1, 0) + encodeVarint(id.toLong()) +
                encodeBytes(2, pub) + encodeBytes(3, sig)
            uploadPayload += encodeMessage(1, spkMsg)
        }
        for ((id, pub) in oneTimePreKeys) {
            val opkMsg = encodeTag(1, 0) + encodeVarint(id.toLong()) + encodeBytes(2, pub)
            uploadPayload += encodeMessage(2, opkMsg)
        }
        // WsClientMessage { upload_pre_keys: UploadPreKeys } — field 3
        return encodeMessage(3, uploadPayload)
    }

    // ── Wire format helpers ────────────────────────────────────────────────

    /** Build auth challenge request frame */
    private fun buildAuthChallengeRequest(): ByteArray {
        // WsClientMessage { auth_challenge_request: {} }
        // Field 1, wire type 2 (bytes/message), empty payload
        return byteArrayOf(0x0A, 0x00) // tag 1, length 0
    }

    /** Build auth response frame */
    private fun buildAuthResponse(nonce: ByteArray): ByteArray {
        val authMsg = buildAuthPrefix() + nonce
        val signer = Ed25519Signer()
        signer.init(true, Ed25519PrivateKeyParameters(identityPriv, 0))
        signer.update(authMsg, 0, authMsg.size)
        val sig = signer.generateSignature()

        // AuthResponse { identity_key: bytes, signature: bytes }
        val authResp = encodeBytes(1, identityPub) + encodeBytes(2, sig)
        // WsClientMessage { auth_response: AuthResponse } — field 2
        return encodeMessage(2, authResp)
    }

    private fun buildAuthPrefix() = Hkdf.INFO_AUTH.toByteArray(Charsets.UTF_8)

    private fun buildFetchMessages(ackIds: List<String>): ByteArray {
        var payload = byteArrayOf()
        for (id in ackIds) {
            payload += encodeString(1, id)
        }
        // WsClientMessage { fetch_messages: FetchMessages } — field 4
        return encodeMessage(4, payload)
    }

    private fun buildSendMessage(correlationId: String, toNymAddress: String, envelope: ByteArray): ByteArray {
        val payload = encodeString(1, correlationId) +
            encodeString(2, toNymAddress) +
            encodeBytes(3, envelope)
        // WsClientMessage { send_message: SendMessage } — field 5
        return encodeMessage(5, payload)
    }

    // ── Minimal protowire encoding ─────────────────────────────────────────

    private fun encodeVarint(v: Long): ByteArray {
        val buf = mutableListOf<Byte>()
        var rem = v
        do {
            var b = (rem and 0x7F).toByte()
            rem = rem ushr 7
            if (rem != 0L) b = (b.toInt() or 0x80).toByte()
            buf.add(b)
        } while (rem != 0L)
        return buf.toByteArray()
    }

    private fun encodeTag(fieldNum: Int, wireType: Int): ByteArray =
        encodeVarint(((fieldNum.toLong() shl 3) or wireType.toLong()))

    private fun encodeBytes(fieldNum: Int, data: ByteArray): ByteArray =
        encodeTag(fieldNum, 2) + encodeVarint(data.size.toLong()) + data

    private fun encodeString(fieldNum: Int, s: String): ByteArray =
        encodeBytes(fieldNum, s.toByteArray(Charsets.UTF_8))

    private fun encodeMessage(fieldNum: Int, inner: ByteArray): ByteArray =
        encodeBytes(fieldNum, inner)

    // ── Parsing helpers ────────────────────────────────────────────────────

    private fun parseServerMessage(data: ByteArray): ServerMsg {
        var pos = 0
        while (pos < data.size) {
            val (tag, n) = readVarint(data, pos); pos += n
            val fieldNum = (tag shr 3).toInt()
            val wireType = (tag and 0x7).toInt()
            if (wireType == 2) {
                val (len, n2) = readVarint(data, pos); pos += n2
                val payload = data.copyOfRange(pos, pos + len.toInt()); pos += len.toInt()
                return when (fieldNum) {
                    1 -> ServerMsg.AuthChallenge(parseNonce(payload))
                    2 -> ServerMsg.AuthOk
                    3 -> ServerMsg.Messages(parseMessages(payload))
                    4 -> ServerMsg.SendAck(parseSendAck(payload))
                    5 -> ServerMsg.Pong
                    6 -> ServerMsg.Error(parseError(payload))
                    7 -> ServerMsg.ProviderInfo(parseProviderInfo(payload))
                    else -> ServerMsg.Unknown
                }
            } else {
                pos += skipField(data, pos, wireType)
            }
        }
        return ServerMsg.Unknown
    }

    private fun parseNonce(data: ByteArray): ByteArray {
        var pos = 0
        while (pos < data.size) {
            val (tag, n) = readVarint(data, pos); pos += n
            val wireType = (tag and 0x7).toInt()
            if (wireType == 2) {
                val (len, n2) = readVarint(data, pos); pos += n2
                return data.copyOfRange(pos, pos + len.toInt())
            }
        }
        return byteArrayOf()
    }

    private fun parseMessages(data: ByteArray): List<StoredMsg> {
        val result = mutableListOf<StoredMsg>()
        var pos = 0
        while (pos < data.size) {
            val (tag, n) = readVarint(data, pos); pos += n
            val wireType = (tag and 0x7).toInt()
            if (wireType == 2 && (tag shr 3).toInt() == 1) {
                val (len, n2) = readVarint(data, pos); pos += n2
                val item = data.copyOfRange(pos, pos + len.toInt()); pos += len.toInt()
                result.add(parseStoredMessage(item))
            } else {
                pos += skipField(data, pos, wireType)
            }
        }
        return result
    }

    private fun parseStoredMessage(data: ByteArray): StoredMsg {
        var id = ""; var envelope = byteArrayOf(); var receivedAt = 0L
        var pos = 0
        while (pos < data.size) {
            val (tag, n) = readVarint(data, pos); pos += n
            val fieldNum = (tag shr 3).toInt()
            val wireType = (tag and 0x7).toInt()
            if (wireType == 2) {
                val (len, n2) = readVarint(data, pos); pos += n2
                val v = data.copyOfRange(pos, pos + len.toInt()); pos += len.toInt()
                when (fieldNum) {
                    1 -> id = String(v, Charsets.UTF_8)
                    2 -> envelope = v
                }
            } else if (wireType == 0) {
                val (v, n2) = readVarint(data, pos); pos += n2
                if (fieldNum == 3) receivedAt = v
            } else {
                pos += skipField(data, pos, wireType)
            }
        }
        return StoredMsg(id, envelope, receivedAt)
    }

    private fun parseSendAck(data: ByteArray): AckResult {
        var correlationId = ""; var ok = false; var errorCode = ""
        var pos = 0
        while (pos < data.size) {
            val (tag, n) = readVarint(data, pos); pos += n
            val fieldNum = (tag shr 3).toInt()
            val wireType = (tag and 0x7).toInt()
            if (wireType == 2) {
                val (len, n2) = readVarint(data, pos); pos += n2
                val v = data.copyOfRange(pos, pos + len.toInt()); pos += len.toInt()
                when (fieldNum) {
                    1 -> correlationId = String(v, Charsets.UTF_8)
                    3 -> errorCode = String(v, Charsets.UTF_8)
                }
            } else if (wireType == 0) {
                val (v, n2) = readVarint(data, pos); pos += n2
                if (fieldNum == 2) ok = v != 0L
            } else {
                pos += skipField(data, pos, wireType)
            }
        }
        return AckResult(correlationId, ok, errorCode)
    }

    private fun parseError(data: ByteArray): String {
        var code = ""
        var pos = 0
        while (pos < data.size) {
            val (tag, n) = readVarint(data, pos); pos += n
            val wireType = (tag and 0x7).toInt()
            if (wireType == 2 && (tag shr 3).toInt() == 1) {
                val (len, n2) = readVarint(data, pos); pos += n2
                code = String(data, pos, len.toInt(), Charsets.UTF_8); pos += len.toInt()
            } else {
                pos += skipField(data, pos, wireType)
            }
        }
        return code
    }

    private fun parseProviderInfo(data: ByteArray): ServerMsg.ProviderInfo {
        var nymAddress = ""
        var onionAddress = ""
        var pos = 0
        while (pos < data.size) {
            val (tag, n) = readVarint(data, pos); pos += n
            val fieldNum = (tag shr 3).toInt()
            val wireType = (tag and 0x7).toInt()
            if (wireType == 2) {
                val (len, n2) = readVarint(data, pos); pos += n2
                val v = String(data, pos, len.toInt(), Charsets.UTF_8); pos += len.toInt()
                when (fieldNum) {
                    1 -> nymAddress = v
                    2 -> onionAddress = v
                }
            } else {
                pos += skipField(data, pos, wireType)
            }
        }
        return ServerMsg.ProviderInfo(nymAddress, onionAddress)
    }

    private fun readVarint(data: ByteArray, start: Int): Pair<Long, Int> {
        var result = 0L; var shift = 0; var pos = start
        while (pos < data.size) {
            val b = data[pos++].toInt() and 0xFF
            result = result or ((b and 0x7F).toLong() shl shift)
            shift += 7
            if (b and 0x80 == 0) break
        }
        return Pair(result, pos - start)
    }

    private fun skipField(data: ByteArray, pos: Int, wireType: Int): Int {
        return when (wireType) {
            0 -> { var p = pos; while (p < data.size && data[p].toInt() and 0x80 != 0) p++; p + 1 - pos }
            2 -> { val (len, n) = readVarint(data, pos); n + len.toInt() }
            5 -> 4
            1 -> 8
            else -> 0
        }
    }

    // ── WebSocket listener ─────────────────────────────────────────────────

    private inner class WsListener : WebSocketListener() {
        private val closedDeferred = CompletableDeferred<Unit>()

        override fun onOpen(webSocket: WebSocket, response: Response) {
            scope.launch { _connectionState.emit(ConnectionState.Authenticating) }
            webSocket.send(buildAuthChallengeRequest().toByteString())
        }

        override fun onMessage(webSocket: WebSocket, bytes: okio.ByteString) {
            scope.launch { handleMessage(webSocket, bytes.toByteArray()) }
        }

        override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
            webSocket.close(1000, null)
        }

        override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
            authed = false
            queue.cancelAll()
            scope.launch { _connectionState.emit(ConnectionState.Disconnected) }
            closedDeferred.complete(Unit)
        }

        override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
            Log.w(TAG, "ws failure: ${t.message}")
            authed = false
            queue.cancelAll()
            scope.launch { _connectionState.emit(ConnectionState.Disconnected) }
            closedDeferred.complete(Unit)
        }

        suspend fun awaitClose() = closedDeferred.await()
    }

    private suspend fun handleMessage(ws: WebSocket, data: ByteArray) {
        when (val msg = parseServerMessage(data)) {
            is ServerMsg.AuthChallenge -> {
                pendingNonce = msg.nonce
                ws.send(buildAuthResponse(msg.nonce).toByteString())
            }
            ServerMsg.AuthOk -> {
                authed = true
                _connectionState.emit(ConnectionState.Connected)
                scope.launch { pollLoop(ws) }
                scope.launch { onAuthenticated(ws) }
            }
            is ServerMsg.Messages -> {
                for (m in msg.items) {
                    onEnvelopeReceived(m.id, m.envelope)
                    pendingAckIds.add(m.id)
                }
            }
            is ServerMsg.SendAck -> queue.complete(msg.result.correlationId, msg.result.ok, msg.result.errorCode)
            ServerMsg.Pong -> {}
            is ServerMsg.ProviderInfo -> onProviderInfo(msg.nymAddress, msg.onionAddress)
            is ServerMsg.Error -> Log.w(TAG, "server error: ${msg.code}")
            ServerMsg.Unknown -> {}
        }
    }

    private suspend fun pollLoop(ws: WebSocket) {
        while (isActive && authed) {
            val ackIds = synchronized(pendingAckIds) {
                val ids = pendingAckIds.toList()
                pendingAckIds.clear()
                ids
            }
            ws.send(buildFetchMessages(ackIds).toByteString())
            delay(30_000)
        }
    }

    private val isActive get() = scope.isActive

    // ── Internal models ────────────────────────────────────────────────────

    private sealed class ServerMsg {
        data class AuthChallenge(val nonce: ByteArray) : ServerMsg()
        object AuthOk : ServerMsg()
        data class Messages(val items: List<StoredMsg>) : ServerMsg()
        data class SendAck(val result: AckResult) : ServerMsg()
        object Pong : ServerMsg()
        data class ProviderInfo(val nymAddress: String, val onionAddress: String) : ServerMsg()
        data class Error(val code: String) : ServerMsg()
        object Unknown : ServerMsg()
    }

    private data class StoredMsg(val id: String, val envelope: ByteArray, val receivedAt: Long)
    private data class AckResult(val correlationId: String, val ok: Boolean, val errorCode: String)
}

private operator fun ByteArray.plus(other: ByteArray): ByteArray {
    val result = ByteArray(size + other.size)
    System.arraycopy(this, 0, result, 0, size)
    System.arraycopy(other, 0, result, size, other.size)
    return result
}
