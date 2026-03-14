package net.evanescent.crypto

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.security.SecureRandom

/**
 * Sealed sender envelope construction and decryption per standards.md §4.
 *
 * Construction:
 *   1. Generate fresh ephemeral X25519 keypair (EPK_priv, EPK_pub)
 *   2. ECDH(EPK_priv, recipient_IK_X25519_pub) → shared secret
 *   3. HKDF-SHA256(shared, salt=0*32, info="Evanescent_SealedSender_v1", len=64) → enc_key || mac_key
 *   4. Encrypt SealedSenderContent: ChaCha20-Poly1305(key=enc_key, nonce=random12, plain=content, aad=EPK_pub)
 *   5. Output SealedEnvelope { ephemeral_key, nonce, ciphertext }
 */
object SealedSender {

    private val ZERO_SALT = ByteArray(32)

    /**
     * Seal a DrMessage for a recipient.
     *
     * @param drMessageBytes      Serialised DrMessage bytes
     * @param recipientIdentityKey  Recipient's Ed25519 public key (32 bytes)
     * @param senderIdentityKey   Sender's Ed25519 public key (32 bytes)
     * @return Serialised SealedEnvelope bytes
     */
    fun seal(
        drMessageBytes: ByteArray,
        recipientIdentityKey: ByteArray,
        senderIdentityKey: ByteArray
    ): ByteArray {
        // Generate ephemeral X25519 keypair.
        val epkPriv = X25519PrivateKeyParameters(SecureRandom())
        val epkPub = epkPriv.generatePublicKey().encoded

        // ECDH with recipient's identity key (converted to X25519).
        val recipientX = X3DH.ed25519PubToX25519Pub(recipientIdentityKey)
        val sharedSecret = x25519(epkPriv, recipientX)

        // Derive keys.
        val derived = Hkdf.expand(sharedSecret, ZERO_SALT, Hkdf.INFO_SEALED_SENDER, 64)
        val encKey = derived.copyOfRange(0, 32)

        // Build inner plaintext.
        val content = serializeSealedSenderContent(senderIdentityKey, drMessageBytes)

        // Encrypt.
        val nonce = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val ciphertext = ChaCha20Poly1305.encrypt(encKey, nonce, content, epkPub)

        // Serialize envelope: [32 epkPub][12 nonce][len(4)][ciphertext]
        return serializeSealedEnvelope(epkPub, nonce, ciphertext)
    }

    /**
     * Unseal a SealedEnvelope.
     *
     * @param envelopeBytes         Serialised SealedEnvelope bytes
     * @param recipientIdentityPriv Recipient's Ed25519 private key seed (32 bytes)
     * @return Pair(senderIdentityKey, drMessageBytes), or throws on decryption failure
     */
    fun unseal(envelopeBytes: ByteArray, recipientIdentityPriv: ByteArray): Pair<ByteArray, ByteArray> {
        val (epkPub, nonce, ciphertext) = deserializeSealedEnvelope(envelopeBytes)

        // ECDH with recipient's identity key.
        val recipientX = X3DH.ed25519ToX25519Priv(recipientIdentityPriv)
        val epkX = X25519PublicKeyParameters(epkPub, 0)
        val sharedSecret = x25519(recipientX, epkX)

        // Derive keys.
        val derived = Hkdf.expand(sharedSecret, ZERO_SALT, Hkdf.INFO_SEALED_SENDER, 64)
        val encKey = derived.copyOfRange(0, 32)

        // Decrypt (throws SecurityException on tag mismatch).
        val contentBytes = ChaCha20Poly1305.decrypt(encKey, nonce, ciphertext, epkPub)

        return deserializeSealedSenderContent(contentBytes)
    }

    private fun x25519(priv: X25519PrivateKeyParameters, pub: X25519PublicKeyParameters): ByteArray {
        val agreement = X25519Agreement()
        agreement.init(priv)
        val out = ByteArray(32)
        agreement.calculateAgreement(pub, out, 0)
        return out
    }

    private fun serializeSealedSenderContent(
        senderIdentityKey: ByteArray,
        drMessage: ByteArray
    ): ByteArray {
        // Wire format: [sender_identity_key(32)][dr_message_len(4)][dr_message]
        // field 2 (nym_address) is RESERVED and omitted.
        val buf = ByteArray(32 + 4 + drMessage.size)
        var pos = 0
        System.arraycopy(senderIdentityKey, 0, buf, pos, 32); pos += 32
        buf[pos++] = (drMessage.size ushr 24).toByte()
        buf[pos++] = (drMessage.size ushr 16).toByte()
        buf[pos++] = (drMessage.size ushr 8).toByte()
        buf[pos++] = drMessage.size.toByte()
        System.arraycopy(drMessage, 0, buf, pos, drMessage.size)
        return buf
    }

    private fun deserializeSealedSenderContent(bytes: ByteArray): Pair<ByteArray, ByteArray> {
        // Wire format: [sender_identity_key(32)][dr_message_len(4)][dr_message]
        var pos = 0
        val senderKey = bytes.copyOfRange(pos, pos + 32); pos += 32
        val drLen = (bytes[pos++].toInt() and 0xFF shl 24) or (bytes[pos++].toInt() and 0xFF shl 16) or
            (bytes[pos++].toInt() and 0xFF shl 8) or (bytes[pos++].toInt() and 0xFF)
        val dr = bytes.copyOfRange(pos, pos + drLen)
        return Pair(senderKey, dr)
    }

    private fun serializeSealedEnvelope(epkPub: ByteArray, nonce: ByteArray, ciphertext: ByteArray): ByteArray {
        val buf = ByteArray(32 + 12 + 4 + ciphertext.size)
        var pos = 0
        System.arraycopy(epkPub, 0, buf, pos, 32); pos += 32
        System.arraycopy(nonce, 0, buf, pos, 12); pos += 12
        buf[pos++] = (ciphertext.size ushr 24).toByte()
        buf[pos++] = (ciphertext.size ushr 16).toByte()
        buf[pos++] = (ciphertext.size ushr 8).toByte()
        buf[pos++] = ciphertext.size.toByte()
        System.arraycopy(ciphertext, 0, buf, pos, ciphertext.size)
        return buf
    }

    private fun deserializeSealedEnvelope(bytes: ByteArray): Triple<ByteArray, ByteArray, ByteArray> {
        var pos = 0
        val epkPub = bytes.copyOfRange(pos, pos + 32); pos += 32
        val nonce = bytes.copyOfRange(pos, pos + 12); pos += 12
        val ctLen = (bytes[pos++].toInt() and 0xFF shl 24) or (bytes[pos++].toInt() and 0xFF shl 16) or
            (bytes[pos++].toInt() and 0xFF shl 8) or (bytes[pos++].toInt() and 0xFF)
        val ct = bytes.copyOfRange(pos, pos + ctLen)
        return Triple(epkPub, nonce, ct)
    }
}
