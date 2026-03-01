package net.evanescent.crypto

import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import java.security.SecureRandom

/**
 * Generates signed prekeys and one-time prekeys for upload to the provider.
 */
class PreKeyGenerator(
    private val identityPriv: ByteArray,
    private val identityPub: ByteArray
) {

    /**
     * Generate a single signed prekey.
     *
     * @param id   Monotonically increasing prekey ID
     * @return Triple(id, publicKey, signature, privateKey)
     */
    fun generateSignedPreKey(id: Int): GeneratedSignedPreKey {
        val priv = X25519PrivateKeyParameters(SecureRandom())
        val pub = priv.generatePublicKey().encoded
        val sig = X3DH.signPreKey(identityPriv, pub)
        return GeneratedSignedPreKey(
            id = id,
            publicKey = pub,
            privateKey = priv.encoded,
            signature = sig
        )
    }

    /**
     * Generate a batch of one-time prekeys.
     *
     * @param startId  First ID in this batch
     * @param count    Number of keys to generate
     */
    fun generateOneTimePreKeys(startId: Int, count: Int): List<GeneratedOneTimePreKey> {
        return (0 until count).map { i ->
            val priv = X25519PrivateKeyParameters(SecureRandom())
            val pub = priv.generatePublicKey().encoded
            GeneratedOneTimePreKey(
                id = startId + i,
                publicKey = pub,
                privateKey = priv.encoded
            )
        }
    }
}

data class GeneratedSignedPreKey(
    val id: Int,
    val publicKey: ByteArray,
    val privateKey: ByteArray,
    val signature: ByteArray
)

data class GeneratedOneTimePreKey(
    val id: Int,
    val publicKey: ByteArray,
    val privateKey: ByteArray
)
