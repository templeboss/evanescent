package net.evanescent.ui.conversation

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import net.evanescent.App
import net.evanescent.DR_TYPE_INITIAL
import net.evanescent.DR_TYPE_REGULAR
import net.evanescent.crypto.*
import net.evanescent.db.*
import net.evanescent.model.MessageDirection
import net.evanescent.model.MessageStatus
import net.evanescent.util.fromHex
import java.util.UUID

class ConversationViewModel(
    app: Application,
    private val contactIdHex: String
) : AndroidViewModel(app) {

    private val appInstance = app as App
    private val db = appInstance.database
    private val contactId = contactIdHex.fromHex()

    val messages = db.messageDao()
        .getForContactFlow(contactId)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    val contact = db.contactDao().getAllFlow()
        .map { contacts -> contacts.firstOrNull { it.identityKey.contentEquals(contactId) } }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)

    fun send(text: String) {
        viewModelScope.launch {
            val contactEntity = db.contactDao().getByKey(contactId) ?: return@launch
            val messageId = UUID.randomUUID().toString()
            val now = System.currentTimeMillis()

            // Store locally first.
            db.messageDao().insert(MessageEntity(
                id = messageId,
                contactId = contactId,
                direction = MessageDirection.OUTBOUND.name,
                plaintext = text,
                timestamp = now,
                status = MessageStatus.SENDING.name
            ))

            try {
                val (drMsgBytes, isInitial, ratchetState) = encryptForContact(contactEntity, text, messageId, now)

                // Prepend DR message type byte.
                val typedDrMsg = byteArrayOf(if (isInitial) DR_TYPE_INITIAL else DR_TYPE_REGULAR) + drMsgBytes

                val envelopeBytes = SealedSender.seal(
                    drMessageBytes = typedDrMsg,
                    recipientIdentityKey = contactEntity.identityKey,
                    senderIdentityKey = appInstance.identityPub
                )

                val toMailboxAddr = contactEntity.mailboxAddr
                    ?: throw IllegalStateException("Contact has no mailbox address — re-add this contact")
                val errCode = appInstance.providerClient.send(contactEntity.providerOnion, toMailboxAddr, envelopeBytes)
                val ok = errCode == null

                if (ok) {
                    // Persist updated ratchet state after successful send.
                    db.sessionDao().upsert(SessionEntity(
                        contactId = contactEntity.identityKey,
                        ratchetState = appInstance.serializeRatchetState(ratchetState)
                    ))
                }

                if (errCode == "PREKEY_EXHAUSTED") {
                    android.util.Log.w("ConversationVM",
                        "contact ${contactIdHex.take(8)}… has exhausted one-time prekeys — message failed")
                }

                db.messageDao().updateStatus(messageId, if (ok) MessageStatus.SENT.name else MessageStatus.FAILED.name)
            } catch (e: Exception) {
                android.util.Log.e("ConversationVM", "send failed: ${e.message}")
                db.messageDao().updateStatus(messageId, MessageStatus.FAILED.name)
            }
        }
    }

    /**
     * Returns Triple(drMsgBytes, isInitialMessage, newRatchetState).
     * - drMsgBytes: the raw DR message payload (WITHOUT the type byte)
     * - isInitialMessage: true when this is the first message (X3DH header embedded)
     * - newRatchetState: the updated state to persist after successful send
     */
    private suspend fun encryptForContact(
        contact: ContactEntity,
        text: String,
        msgId: String,
        timestamp: Long
    ): Triple<ByteArray, Boolean, RatchetState> {
        val sessionEntity = db.sessionDao().get(contact.identityKey)

        return if (sessionEntity == null) {
            // No session — run X3DH, create initial message.
            val (bundle, ratchetState) = establishSession(contact)
            val content = serializeMessageContent(text, timestamp, msgId)
            val (newState, innerDrBytes) = DoubleRatchet.encrypt(ratchetState, content)

            // Embed X3DH header into the payload: [EK_pub(32)][spk_id(4)][opk_id(4)][DR bytes]
            val x3dhHeader = bundle.ephemeralPublic +
                intToBytes(bundle.bundle.signedPrekeyId) +
                intToBytes(bundle.oneTimePrekeyId)
            Triple(x3dhHeader + innerDrBytes, true, newState)
        } else {
            val ratchetState = appInstance.deserializeRatchetState(sessionEntity.ratchetState)
            val content = serializeMessageContent(text, timestamp, msgId)
            val (newState, drMsgBytes) = DoubleRatchet.encrypt(ratchetState, content)
            Triple(drMsgBytes, false, newState)
        }
    }

    /**
     * Fetch a PreKeyBundle from the contact's provider via GetPreKeys WS message:
     * 1. Send GetPreKeys to our provider specifying contact's mailbox and provider onion.
     * 2. Provider fetches from the contact's provider and returns the bundle directly.
     * 3. Verify SPK signature.
     * 4. Run X3DH.initiate().
     * 5. Return (X3DHResult, initial RatchetState).
     */
    private suspend fun establishSession(
        contact: ContactEntity
    ): Pair<X3DHInitResult, RatchetState> {
        val targetMailboxAddr = contact.mailboxAddr
            ?: throw IllegalStateException("Contact has no mailbox address — re-add this contact")

        // Request the PreKeyBundle via the new GetPreKeys WS message.
        val bundleBytes = appInstance.providerClient.getPreKeys(
            targetMailboxAddr = targetMailboxAddr,
            targetProviderOnion = contact.providerOnion
        ) ?: error("PreKeyBundle not received — provider timed out or contact has no prekeys")

        // Parse the bundle.
        val bundle = parsePreKeyBundle(bundleBytes)

        // Verify SPK signature.
        check(X3DH.verifyPreKey(bundle.identityKey, bundle.signedPrekey, bundle.signedPrekeySig)) {
            "Invalid SPK signature in PreKeyBundle — possible tampering"
        }

        // Run X3DH.
        val x3dhBundle = PreKeyBundle(
            identityKey = bundle.identityKey,
            signedPrekeyId = bundle.signedPrekeyId,
            signedPrekey = bundle.signedPrekey,
            signedPrekeySig = bundle.signedPrekeySig,
            oneTimePrekeyId = bundle.oneTimePrekeyId,
            oneTimePrekey = bundle.oneTimePrekey.takeIf { it.isNotEmpty() }
        )
        val x3dhResult = X3DH.initiate(
            aliceIdentityPriv = appInstance.identityPriv,
            aliceIdentityPub = appInstance.identityPub,
            bobBundle = x3dhBundle
        )

        val ratchetState = DoubleRatchet.initAlice(x3dhResult.masterSecret, bundle.signedPrekey)
        return Pair(X3DHInitResult(x3dhResult.ephemeralPublic, bundle, x3dhResult.oneTimePrekeyId), ratchetState)
    }

    // ── PreKeyBundle proto parsing ──────────────────────────────────────────

    private data class ParsedBundle(
        val identityKey: ByteArray,
        val signedPrekeyId: Int,
        val signedPrekey: ByteArray,
        val signedPrekeySig: ByteArray,
        val oneTimePrekeyId: Int,
        val oneTimePrekey: ByteArray
    )

    private data class X3DHInitResult(
        val ephemeralPublic: ByteArray,
        val bundle: ParsedBundle,
        val oneTimePrekeyId: Int
    )

    private fun parsePreKeyBundle(bytes: ByteArray): ParsedBundle {
        var identityKey = byteArrayOf()
        var signedPrekeyId = 0
        var signedPrekey = byteArrayOf()
        var signedPrekeySig = byteArrayOf()
        var oneTimePrekeyId = 0
        var oneTimePrekey = byteArrayOf()
        var pos = 0
        while (pos < bytes.size) {
            val (tag, n) = readVarint(bytes, pos); pos += n
            val fieldNum = (tag shr 3).toInt()
            val wireType = (tag and 0x7).toInt()
            if (wireType == 2) {
                val (len, n2) = readVarint(bytes, pos); pos += n2
                val v = bytes.copyOfRange(pos, pos + len.toInt()); pos += len.toInt()
                when (fieldNum) {
                    1 -> identityKey = v
                    3 -> signedPrekey = v
                    4 -> signedPrekeySig = v
                    6 -> oneTimePrekey = v
                }
            } else if (wireType == 0) {
                val (v, n2) = readVarint(bytes, pos); pos += n2
                when (fieldNum) {
                    2 -> signedPrekeyId = v.toInt()
                    5 -> oneTimePrekeyId = v.toInt()
                }
            } else {
                pos += skipField(bytes, pos, wireType)
            }
        }
        return ParsedBundle(identityKey, signedPrekeyId, signedPrekey, signedPrekeySig, oneTimePrekeyId, oneTimePrekey)
    }

    // ── Serialization helpers ──────────────────────────────────────────────

    private fun serializeMessageContent(text: String, sentAt: Long, messageId: String): ByteArray {
        val textBytes = text.toByteArray(Charsets.UTF_8)
        val idBytes = messageId.toByteArray(Charsets.UTF_8)
        val buf = ByteArray(2 + textBytes.size + 8 + 2 + idBytes.size)
        var pos = 0
        buf[pos++] = (textBytes.size ushr 8).toByte()
        buf[pos++] = textBytes.size.toByte()
        System.arraycopy(textBytes, 0, buf, pos, textBytes.size); pos += textBytes.size
        for (i in 7 downTo 0) buf[pos++] = (sentAt ushr (8 * i)).toByte()
        buf[pos++] = (idBytes.size ushr 8).toByte()
        buf[pos++] = idBytes.size.toByte()
        System.arraycopy(idBytes, 0, buf, pos, idBytes.size)
        return buf
    }

    private fun intToBytes(v: Int) = byteArrayOf(
        (v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte()
    )

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
