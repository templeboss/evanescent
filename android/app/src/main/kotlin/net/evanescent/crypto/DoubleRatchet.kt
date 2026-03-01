package net.evanescent.crypto

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.engines.ChaCha7539Engine
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.security.SecureRandom

/**
 * Double Ratchet implementation per the Signal Double Ratchet specification and standards.md §3.
 */
object DoubleRatchet {

    const val MAX_SKIP = 1000
    const val MAX_CHAIN = 2000

    /**
     * Initialise a new ratchet state for the initiator (Alice), after X3DH.
     *
     * @param masterSecret  32-byte shared secret from X3DH
     * @param bobSpkPublic  Bob's signed prekey public key (32 bytes) — Alice's initial DH ratchet target
     */
    fun initAlice(masterSecret: ByteArray, bobSpkPublic: ByteArray): RatchetState {
        val selfKp = generateX25519KeyPair()
        val dhOut = dhX25519(selfKp.first, X25519PublicKeyParameters(bobSpkPublic, 0))
        val (rk, ck) = kdfRK(masterSecret, dhOut)
        return RatchetState(
            dhSelfPublic = selfKp.second,
            dhSelfPrivate = selfKp.first.encoded,
            dhRemotePublic = bobSpkPublic,
            rootKey = rk,
            chainKeySend = ck,
            chainKeyRecv = ByteArray(32),
            sendCount = 0,
            recvCount = 0,
            prevSendCount = 0,
            skippedKeys = mutableMapOf()
        )
    }

    /**
     * Initialise a new ratchet state for the responder (Bob), after X3DH.
     *
     * @param masterSecret    32-byte shared secret from X3DH
     * @param bobSpkPrivate   Bob's signed prekey private key (32 bytes)
     * @param bobSpkPublic    Bob's signed prekey public key (32 bytes)
     */
    fun initBob(masterSecret: ByteArray, bobSpkPrivate: ByteArray, bobSpkPublic: ByteArray): RatchetState {
        return RatchetState(
            dhSelfPublic = bobSpkPublic,
            dhSelfPrivate = bobSpkPrivate,
            dhRemotePublic = ByteArray(32),
            rootKey = masterSecret,
            chainKeySend = ByteArray(32),
            chainKeyRecv = ByteArray(32),
            sendCount = 0,
            recvCount = 0,
            prevSendCount = 0,
            skippedKeys = mutableMapOf()
        )
    }

    /**
     * Encrypt a plaintext message. Returns (updated state, DrMessageBytes).
     */
    fun encrypt(state: RatchetState, plaintext: ByteArray): Pair<RatchetState, ByteArray> {
        val (newState, mk) = ratchetSend(state)
        val header = MessageHeader(
            dhRatchetKey = newState.dhSelfPublic,
            previousCounter = newState.prevSendCount,
            messageCounter = newState.sendCount - 1
        )
        val headerBytes = header.serialize()
        val ciphertext = aeadEncrypt(mk, plaintext, headerBytes, newState.sendCount - 1)
        val drMsg = DrMessageBytes(messageHeader = headerBytes, ciphertext = ciphertext)
        return Pair(newState, drMsg.serialize())
    }

    /**
     * Decrypt a DrMessage. Returns (updated state, plaintext).
     * Throws on decryption failure.
     */
    fun decrypt(state: RatchetState, drMsgBytes: ByteArray): Pair<RatchetState, ByteArray> {
        val drMsg = DrMessageBytes.deserialize(drMsgBytes)
        val header = MessageHeader.deserialize(drMsg.messageHeader)

        // Check skipped keys.
        val skipKey = SkippedKeyId(header.dhRatchetKey, header.messageCounter)
        val skippedMk = state.skippedKeys[skipKey]
        if (skippedMk != null) {
            val newSkipped = state.skippedKeys.toMutableMap().also { it.remove(skipKey) }
            val plaintext = aeadDecrypt(skippedMk, drMsg.ciphertext, drMsg.messageHeader, header.messageCounter)
            return Pair(state.copy(skippedKeys = newSkipped), plaintext)
        }

        var newState = state
        if (!header.dhRatchetKey.contentEquals(state.dhRemotePublic)) {
            newState = skipMessageKeys(newState, header.previousCounter)
            newState = dhRatchet(newState, header.dhRatchetKey)
        }
        newState = skipMessageKeys(newState, header.messageCounter)
        val (finalState, mk) = ratchetRecv(newState)
        val plaintext = aeadDecrypt(mk, drMsg.ciphertext, drMsg.messageHeader, header.messageCounter)
        return Pair(finalState, plaintext)
    }

    private fun skipMessageKeys(state: RatchetState, until: Int): RatchetState {
        if (state.recvCount + MAX_SKIP < until) {
            throw IllegalStateException("Too many skipped messages")
        }
        if (state.chainKeyRecv.all { it == 0.toByte() }) return state

        var s = state
        while (s.recvCount < until) {
            val mk = kdfMK(s.chainKeyRecv)
            val newCk = kdfCK(s.chainKeyRecv)
            val skipKey = SkippedKeyId(s.dhRemotePublic, s.recvCount)
            val newSkipped = s.skippedKeys.toMutableMap().also {
                if (it.size >= MAX_SKIP) throw IllegalStateException("Skipped key store full")
                it[skipKey] = mk
            }
            s = s.copy(chainKeyRecv = newCk, recvCount = s.recvCount + 1, skippedKeys = newSkipped)
        }
        return s
    }

    private fun dhRatchet(state: RatchetState, remotePub: ByteArray): RatchetState {
        val pn = state.sendCount
        val dhOut1 = dhX25519(X25519PrivateKeyParameters(state.dhSelfPrivate, 0), X25519PublicKeyParameters(remotePub, 0))
        val (rk1, ckRecv) = kdfRK(state.rootKey, dhOut1)

        val newKp = generateX25519KeyPair()
        val dhOut2 = dhX25519(newKp.first, X25519PublicKeyParameters(remotePub, 0))
        val (rk2, ckSend) = kdfRK(rk1, dhOut2)

        return state.copy(
            dhSelfPublic = newKp.second,
            dhSelfPrivate = newKp.first.encoded,
            dhRemotePublic = remotePub,
            rootKey = rk2,
            chainKeySend = ckSend,
            chainKeyRecv = ckRecv,
            sendCount = 0,
            recvCount = 0,
            prevSendCount = pn
        )
    }

    private fun ratchetSend(state: RatchetState): Pair<RatchetState, ByteArray> {
        val mk = kdfMK(state.chainKeySend)
        val newCk = kdfCK(state.chainKeySend)
        return Pair(state.copy(chainKeySend = newCk, sendCount = state.sendCount + 1), mk)
    }

    private fun ratchetRecv(state: RatchetState): Pair<RatchetState, ByteArray> {
        val mk = kdfMK(state.chainKeyRecv)
        val newCk = kdfCK(state.chainKeyRecv)
        return Pair(state.copy(chainKeyRecv = newCk, recvCount = state.recvCount + 1), mk)
    }

    /** Root KDF: HKDF-SHA256(input=dhOut, salt=rk, info=INFO_DR_RK) → 64 bytes → (newRK, newCK) */
    private fun kdfRK(rk: ByteArray, dhOut: ByteArray): Pair<ByteArray, ByteArray> {
        val out = Hkdf.expand(dhOut, rk, Hkdf.INFO_DR_RK, 64)
        return Pair(out.copyOfRange(0, 32), out.copyOfRange(32, 64))
    }

    /** Chain KDF: HMAC-SHA256(key=CK, data=0x02) → new CK */
    private fun kdfCK(ck: ByteArray): ByteArray = hmacSha256(ck, byteArrayOf(0x02))

    /** Message key: HMAC-SHA256(key=CK, data=0x01) → MK */
    private fun kdfMK(ck: ByteArray): ByteArray = hmacSha256(ck, byteArrayOf(0x01))

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val hmac = HMac(org.bouncycastle.crypto.digests.SHA256Digest())
        hmac.init(KeyParameter(key))
        hmac.update(data, 0, data.size)
        val out = ByteArray(hmac.macSize)
        hmac.doFinal(out, 0)
        return out
    }

    /**
     * ChaCha20-Poly1305 AEAD encrypt.
     * Nonce: counter_u32_be (4 bytes) || 0x00 * 8 = 12 bytes
     * AAD: serialised MessageHeader bytes
     */
    private fun aeadEncrypt(key: ByteArray, plaintext: ByteArray, aad: ByteArray, counter: Int): ByteArray {
        val nonce = buildNonce(counter)
        return ChaCha20Poly1305.encrypt(key, nonce, plaintext, aad)
    }

    private fun aeadDecrypt(key: ByteArray, ciphertext: ByteArray, aad: ByteArray, counter: Int): ByteArray {
        val nonce = buildNonce(counter)
        return ChaCha20Poly1305.decrypt(key, nonce, ciphertext, aad)
    }

    private fun buildNonce(counter: Int): ByteArray {
        val nonce = ByteArray(12)
        nonce[0] = (counter ushr 24).toByte()
        nonce[1] = (counter ushr 16).toByte()
        nonce[2] = (counter ushr 8).toByte()
        nonce[3] = counter.toByte()
        // bytes [4:12] remain zero
        return nonce
    }

    private fun dhX25519(priv: X25519PrivateKeyParameters, pub: X25519PublicKeyParameters): ByteArray {
        val agreement = X25519Agreement()
        agreement.init(priv)
        val out = ByteArray(32)
        agreement.calculateAgreement(pub, out, 0)
        return out
    }

    private fun generateX25519KeyPair(): Pair<X25519PrivateKeyParameters, ByteArray> {
        val priv = X25519PrivateKeyParameters(SecureRandom())
        val pub = priv.generatePublicKey().encoded
        return Pair(priv, pub)
    }
}

data class RatchetState(
    val dhSelfPublic: ByteArray,
    val dhSelfPrivate: ByteArray,
    val dhRemotePublic: ByteArray,
    val rootKey: ByteArray,
    val chainKeySend: ByteArray,
    val chainKeyRecv: ByteArray,
    val sendCount: Int,
    val recvCount: Int,
    val prevSendCount: Int,
    val skippedKeys: Map<SkippedKeyId, ByteArray>
) {
    fun copy(
        dhSelfPublic: ByteArray = this.dhSelfPublic,
        dhSelfPrivate: ByteArray = this.dhSelfPrivate,
        dhRemotePublic: ByteArray = this.dhRemotePublic,
        rootKey: ByteArray = this.rootKey,
        chainKeySend: ByteArray = this.chainKeySend,
        chainKeyRecv: ByteArray = this.chainKeyRecv,
        sendCount: Int = this.sendCount,
        recvCount: Int = this.recvCount,
        prevSendCount: Int = this.prevSendCount,
        skippedKeys: Map<SkippedKeyId, ByteArray> = this.skippedKeys
    ) = RatchetState(dhSelfPublic, dhSelfPrivate, dhRemotePublic, rootKey, chainKeySend, chainKeyRecv, sendCount, recvCount, prevSendCount, skippedKeys)
}

data class SkippedKeyId(val dhPublic: ByteArray, val messageCounter: Int) {
    override fun equals(other: Any?): Boolean {
        if (other !is SkippedKeyId) return false
        return dhPublic.contentEquals(other.dhPublic) && messageCounter == other.messageCounter
    }
    override fun hashCode(): Int = 31 * dhPublic.contentHashCode() + messageCounter
}

data class MessageHeader(val dhRatchetKey: ByteArray, val previousCounter: Int, val messageCounter: Int) {
    fun serialize(): ByteArray {
        // Minimal serialisation: [32 bytes DH key][4 bytes PN][4 bytes N]
        val out = ByteArray(40)
        System.arraycopy(dhRatchetKey, 0, out, 0, 32)
        out[32] = (previousCounter ushr 24).toByte()
        out[33] = (previousCounter ushr 16).toByte()
        out[34] = (previousCounter ushr 8).toByte()
        out[35] = previousCounter.toByte()
        out[36] = (messageCounter ushr 24).toByte()
        out[37] = (messageCounter ushr 16).toByte()
        out[38] = (messageCounter ushr 8).toByte()
        out[39] = messageCounter.toByte()
        return out
    }

    companion object {
        fun deserialize(bytes: ByteArray): MessageHeader {
            val dhKey = bytes.copyOfRange(0, 32)
            val pn = (bytes[32].toInt() and 0xFF shl 24) or (bytes[33].toInt() and 0xFF shl 16) or
                (bytes[34].toInt() and 0xFF shl 8) or (bytes[35].toInt() and 0xFF)
            val n = (bytes[36].toInt() and 0xFF shl 24) or (bytes[37].toInt() and 0xFF shl 16) or
                (bytes[38].toInt() and 0xFF shl 8) or (bytes[39].toInt() and 0xFF)
            return MessageHeader(dhKey, pn, n)
        }
    }
}

private data class DrMessageBytes(val messageHeader: ByteArray, val ciphertext: ByteArray) {
    fun serialize(): ByteArray {
        val out = ByteArray(4 + messageHeader.size + 4 + ciphertext.size)
        var pos = 0
        out[pos++] = (messageHeader.size ushr 24).toByte()
        out[pos++] = (messageHeader.size ushr 16).toByte()
        out[pos++] = (messageHeader.size ushr 8).toByte()
        out[pos++] = messageHeader.size.toByte()
        System.arraycopy(messageHeader, 0, out, pos, messageHeader.size)
        pos += messageHeader.size
        out[pos++] = (ciphertext.size ushr 24).toByte()
        out[pos++] = (ciphertext.size ushr 16).toByte()
        out[pos++] = (ciphertext.size ushr 8).toByte()
        out[pos++] = ciphertext.size.toByte()
        System.arraycopy(ciphertext, 0, out, pos, ciphertext.size)
        return out
    }

    companion object {
        fun deserialize(bytes: ByteArray): DrMessageBytes {
            var pos = 0
            val hLen = (bytes[pos++].toInt() and 0xFF shl 24) or (bytes[pos++].toInt() and 0xFF shl 16) or
                (bytes[pos++].toInt() and 0xFF shl 8) or (bytes[pos++].toInt() and 0xFF)
            val header = bytes.copyOfRange(pos, pos + hLen)
            pos += hLen
            val cLen = (bytes[pos++].toInt() and 0xFF shl 24) or (bytes[pos++].toInt() and 0xFF shl 16) or
                (bytes[pos++].toInt() and 0xFF shl 8) or (bytes[pos++].toInt() and 0xFF)
            val ct = bytes.copyOfRange(pos, pos + cLen)
            return DrMessageBytes(header, ct)
        }
    }
}
