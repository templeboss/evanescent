package net.evanescent

import android.app.Application
import android.util.Log
import kotlinx.coroutines.flow.MutableSharedFlow
import net.evanescent.crypto.*
import net.evanescent.db.AppDatabase
import net.evanescent.db.MessageEntity
import net.evanescent.db.SessionEntity
import net.evanescent.model.MessageDirection
import net.evanescent.model.MessageStatus
import net.evanescent.provider.PreKeyUploader
import net.evanescent.provider.ProviderClient
import java.util.UUID

private const val TAG = "Evanescent"

/** Prefix byte in `SealedSenderContent.dr_message` for initial X3DH messages. */
const val DR_TYPE_REGULAR: Byte = 0x00
const val DR_TYPE_INITIAL: Byte = 0x01

class App : Application() {

    lateinit var keyManager: KeyManager
        private set

    lateinit var database: AppDatabase
        private set

    lateinit var providerClient: ProviderClient
        private set

    lateinit var identityPub: ByteArray
        private set

    lateinit var identityPriv: ByteArray
        private set

    /** Provider's Nym address — delivered via ProviderInfo WS message after auth. */
    @Volatile var providerNymAddr: String = ""
        private set

    /** Provider's .onion address — delivered via ProviderInfo WS message after auth. */
    @Volatile var providerOnionAddr: String = ""
        private set

    /** This user's own mailbox address — 32 raw bytes — delivered via ProviderInfo after auth. */
    @Volatile var myMailboxAddr: ByteArray = byteArrayOf()
        private set

    /**
     * Emits (senderIdentityKey, PreKeyBundle proto bytes) when a prekey bundle
     * arrives in the mailbox. ConversationViewModel awaits this to establish sessions.
     */
    // replay=8 so bundles arriving before the collector starts are not lost.
    val prekeyBundleFlow: MutableSharedFlow<Pair<ByteArray, ByteArray>> =
        MutableSharedFlow(replay = 8)

    override fun onCreate() {
        super.onCreate()

        keyManager = KeyManager(this)

        val (priv, pub) = keyManager.getOrCreateIdentityKeyPair()
        identityPriv = priv
        identityPub = pub
        Log.d(TAG, "Identity key loaded (${pub.size} bytes)")

        val dbKey = keyManager.getDatabaseKey()
        database = AppDatabase.getInstance(this, dbKey)

        val preKeyUploader = PreKeyUploader(
            preKeyDao = database.preKeyDao(),
            generator = PreKeyGenerator(identityPriv, identityPub),
            uploadKeys = { signedKeys, oneTimeKeys ->
                val frame = providerClient.buildUploadPreKeysFrame(
                    signedPreKeys = signedKeys.map { Triple(it.prekeyId, it.publicKey, it.signature ?: byteArrayOf()) },
                    oneTimePreKeys = oneTimeKeys.map { Pair(it.prekeyId, it.publicKey) }
                )
                providerClient.sendFrame(frame)
            }
        )

        providerClient = ProviderClient(
            identityPriv = identityPriv,
            identityPub = identityPub,
            onEnvelopeReceived = { id, envelope ->
                handleIncomingEnvelope(id, envelope)
            },
            onProviderInfo = { nymAddr, onionAddr, mailboxAddr ->
                providerNymAddr = nymAddr
                providerOnionAddr = onionAddr
                myMailboxAddr = mailboxAddr
                Log.d(TAG, "Provider Nym address: $nymAddr")
            },
            onAuthenticated = {
                try {
                    preKeyUploader.checkAndUpload()
                } catch (e: Exception) {
                    Log.e(TAG, "prekey upload failed: ${e.message}")
                }
            }
        )
    }

    private suspend fun handleIncomingEnvelope(id: String, envelope: ByteArray) {
        if (id.startsWith("pkb.")) {
            // This is a PreKeyBundle response — emit it so ConversationViewModel can use it.
            try {
                val identityKey = parseIdentityKeyFromBundle(envelope)
                prekeyBundleFlow.emit(Pair(identityKey, envelope))
                Log.d(TAG, "incoming prekey bundle for contact ${identityKey.take(4)}")
            } catch (e: Exception) {
                Log.e(TAG, "failed to parse prekey bundle: ${e.message}")
            }
            return
        }

        // Regular sealed sender envelope.
        try {
            val (senderIdentityKey, senderNymAddr, drMsgBytes) =
                SealedSender.unseal(envelope, identityPriv)

            val contact = database.contactDao().getByKey(senderIdentityKey) ?: run {
                Log.w(TAG, "message from unknown contact — ignoring")
                return
            }

            val (newState, plaintext) = decryptDrMessage(senderIdentityKey, drMsgBytes)

            // Persist updated ratchet state.
            database.sessionDao().upsert(SessionEntity(
                contactId = senderIdentityKey,
                ratchetState = serializeRatchetState(newState)
            ))

            // Parse message content.
            val content = parseMessageContent(plaintext)
            database.messageDao().insert(MessageEntity(
                id = content.messageId.ifEmpty { UUID.randomUUID().toString() },
                contactId = senderIdentityKey,
                direction = MessageDirection.INBOUND.name,
                plaintext = content.text,
                timestamp = content.sentAt,
                status = MessageStatus.DELIVERED.name
            ))
        } catch (e: Exception) {
            Log.e(TAG, "failed to decrypt incoming message: ${e.message}")
        }
    }

    /**
     * Decrypt a DR message, handling both initial (X3DH) and regular messages.
     * Returns (updated RatchetState, plaintext bytes).
     */
    private suspend fun decryptDrMessage(
        senderIdentityKey: ByteArray,
        drMsgBytes: ByteArray
    ): Pair<RatchetState, ByteArray> {
        if (drMsgBytes.isEmpty()) throw IllegalArgumentException("Empty DR message")

        return when (drMsgBytes[0]) {
            DR_TYPE_INITIAL -> {
                // Initial message: establish Bob's ratchet then decrypt.
                if (drMsgBytes.size < 1 + 32 + 4 + 4) {
                    throw IllegalArgumentException("Initial DR message too short")
                }
                var pos = 1
                val ephemeralPub = drMsgBytes.copyOfRange(pos, pos + 32); pos += 32
                val spkId = readInt32(drMsgBytes, pos); pos += 4
                val opkId = readInt32(drMsgBytes, pos); pos += 4
                val innerDrBytes = drMsgBytes.copyOfRange(pos, drMsgBytes.size)

                // Look up the SPK private key used.
                val spkEntity = database.preKeyDao().getByIdAndType(spkId, "SIGNED")
                    ?: throw IllegalStateException("SPK id=$spkId not found in local DB")

                // Look up and consume the OPK private key (if used).
                val opkPriv: ByteArray? = if (opkId != 0) {
                    val opkEntity = database.preKeyDao().getByIdAndType(opkId, "ONE_TIME")
                        ?: throw IllegalStateException("OPK id=$opkId not found in local DB")
                    database.preKeyDao().markUsed(opkEntity.rowId)
                    opkEntity.privateKey
                } else null

                val masterSecret = X3DH.respond(
                    bobIdentityPriv = identityPriv,
                    bobSpkPriv = spkEntity.privateKey,
                    bobOpkPriv = opkPriv,
                    aliceIdentityPub = senderIdentityKey,
                    aliceEphemeralPub = ephemeralPub
                )
                val state = DoubleRatchet.initBob(masterSecret, spkEntity.privateKey, spkEntity.publicKey)
                DoubleRatchet.decrypt(state, innerDrBytes)
            }
            else -> {
                // Regular message: DR_TYPE_REGULAR (0x00) or legacy (no type byte).
                val innerBytes = if (drMsgBytes[0] == DR_TYPE_REGULAR) {
                    drMsgBytes.copyOfRange(1, drMsgBytes.size)
                } else {
                    drMsgBytes  // backward-compat: treat whole buffer as DR message
                }
                val sessionEntity = database.sessionDao().get(senderIdentityKey)
                    ?: throw IllegalStateException("No session for sender — expected initial message")
                val state = deserializeRatchetState(sessionEntity.ratchetState)
                DoubleRatchet.decrypt(state, innerBytes)
            }
        }
    }

    // ── Proto helpers ──────────────────────────────────────────────────────────

    /** Extract identity_key (field 1, bytes, 32 bytes) from a PreKeyBundle proto. */
    private fun parseIdentityKeyFromBundle(bundleBytes: ByteArray): ByteArray {
        var pos = 0
        while (pos < bundleBytes.size) {
            val (tag, n) = readVarint(bundleBytes, pos); pos += n
            val fieldNum = (tag shr 3).toInt()
            val wireType = (tag and 0x7).toInt()
            if (wireType == 2) {
                val (len, n2) = readVarint(bundleBytes, pos); pos += n2
                val v = bundleBytes.copyOfRange(pos, pos + len.toInt()); pos += len.toInt()
                if (fieldNum == 1) return v
            } else {
                pos += skipField(bundleBytes, pos, wireType)
            }
        }
        throw IllegalArgumentException("identity_key not found in PreKeyBundle")
    }

    private data class MessageContent(val text: String, val sentAt: Long, val messageId: String)

    private fun parseMessageContent(bytes: ByteArray): MessageContent {
        var pos = 0
        val textLen = (bytes[pos++].toInt() and 0xFF shl 8) or (bytes[pos++].toInt() and 0xFF)
        val text = String(bytes, pos, textLen, Charsets.UTF_8); pos += textLen
        var sentAt = 0L
        for (i in 7 downTo 0) sentAt = sentAt or ((bytes[pos++].toLong() and 0xFF) shl (8 * i))
        val idLen = (bytes[pos++].toInt() and 0xFF shl 8) or (bytes[pos++].toInt() and 0xFF)
        val messageId = if (pos + idLen <= bytes.size) String(bytes, pos, idLen, Charsets.UTF_8) else ""
        return MessageContent(text, sentAt, messageId)
    }

    // ── Ratchet state serialization (matches ConversationViewModel) ────────────

    fun serializeRatchetState(state: RatchetState): ByteArray {
        val skBytes = state.skippedKeys.entries.flatMap { (k, v) ->
            k.dhPublic.toList() + listOf(
                (k.messageCounter ushr 24).toByte(),
                (k.messageCounter ushr 16).toByte(),
                (k.messageCounter ushr 8).toByte(),
                k.messageCounter.toByte()
            ) + v.toList()
        }.toByteArray()

        return state.dhSelfPublic + state.dhSelfPrivate + state.dhRemotePublic +
            state.rootKey + state.chainKeySend + state.chainKeyRecv +
            intToBytes(state.sendCount) + intToBytes(state.recvCount) +
            intToBytes(state.prevSendCount) +
            intToBytes(skBytes.size) + skBytes
    }

    fun deserializeRatchetState(bytes: ByteArray): RatchetState {
        var pos = 0
        fun readBytes(n: Int): ByteArray = bytes.copyOfRange(pos, pos + n).also { pos += n }
        fun readInt(): Int {
            val v = (bytes[pos].toInt() and 0xFF shl 24) or (bytes[pos+1].toInt() and 0xFF shl 16) or
                (bytes[pos+2].toInt() and 0xFF shl 8) or (bytes[pos+3].toInt() and 0xFF)
            pos += 4; return v
        }
        val dhSelfPub = readBytes(32)
        val dhSelfPriv = readBytes(32)
        val dhRemotePub = readBytes(32)
        val rk = readBytes(32)
        val ckSend = readBytes(32)
        val ckRecv = readBytes(32)
        val sendCount = readInt()
        val recvCount = readInt()
        val prevSendCount = readInt()
        val skLen = readInt()
        val skBytes = readBytes(skLen)

        val skippedKeys = mutableMapOf<SkippedKeyId, ByteArray>()
        var skPos = 0
        val entrySize = 32 + 4 + 32
        while (skPos + entrySize <= skBytes.size) {
            val dhPub = skBytes.copyOfRange(skPos, skPos + 32); skPos += 32
            val counter = (skBytes[skPos].toInt() and 0xFF shl 24) or
                (skBytes[skPos+1].toInt() and 0xFF shl 16) or
                (skBytes[skPos+2].toInt() and 0xFF shl 8) or
                (skBytes[skPos+3].toInt() and 0xFF); skPos += 4
            val mk = skBytes.copyOfRange(skPos, skPos + 32); skPos += 32
            skippedKeys[SkippedKeyId(dhPub, counter)] = mk
        }

        return RatchetState(dhSelfPub, dhSelfPriv, dhRemotePub, rk, ckSend, ckRecv, sendCount, recvCount, prevSendCount, skippedKeys)
    }

    // ── Utility ────────────────────────────────────────────────────────────────

    private fun intToBytes(v: Int) = byteArrayOf(
        (v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte()
    )

    private fun readInt32(data: ByteArray, pos: Int): Int =
        (data[pos].toInt() and 0xFF shl 24) or (data[pos+1].toInt() and 0xFF shl 16) or
        (data[pos+2].toInt() and 0xFF shl 8) or (data[pos+3].toInt() and 0xFF)

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
}

private operator fun ByteArray.plus(other: ByteArray): ByteArray {
    val result = ByteArray(size + other.size)
    System.arraycopy(this, 0, result, 0, size)
    System.arraycopy(other, 0, result, size, other.size)
    return result
}

private fun ByteArray.take(n: Int): String = toList().take(n).map { "%02x".format(it) }.joinToString("")
