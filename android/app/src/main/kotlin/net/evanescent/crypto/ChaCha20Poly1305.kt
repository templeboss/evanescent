package net.evanescent.crypto

import org.bouncycastle.crypto.engines.ChaCha7539Engine
import org.bouncycastle.crypto.macs.Poly1305
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV

/**
 * ChaCha20-Poly1305 AEAD per RFC 8439.
 * 32-byte key, 12-byte nonce.
 * Output: ciphertext || 16-byte Poly1305 tag.
 */
object ChaCha20Poly1305 {

    fun encrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray {
        require(key.size == 32) { "key must be 32 bytes" }
        require(nonce.size == 12) { "nonce must be 12 bytes" }

        val ciphertext = ByteArray(plaintext.size)
        val engine = ChaCha7539Engine()
        engine.init(true, ParametersWithIV(KeyParameter(key), nonce))

        // Generate Poly1305 key from ChaCha20 keystream block 0.
        val poly1305Key = ByteArray(64)
        engine.processBytes(poly1305Key, 0, 64, poly1305Key, 0)

        // Encrypt plaintext (from block 1 onward).
        engine.processBytes(plaintext, 0, plaintext.size, ciphertext, 0)

        // Compute Poly1305 tag over: AAD || pad || ciphertext || pad || lengths.
        val tag = poly1305Tag(poly1305Key.copyOfRange(0, 32), aad, ciphertext)
        return ciphertext + tag
    }

    fun decrypt(key: ByteArray, nonce: ByteArray, ciphertextWithTag: ByteArray, aad: ByteArray): ByteArray {
        require(key.size == 32) { "key must be 32 bytes" }
        require(nonce.size == 12) { "nonce must be 12 bytes" }
        require(ciphertextWithTag.size >= 16) { "ciphertext too short" }

        val ciphertext = ciphertextWithTag.copyOfRange(0, ciphertextWithTag.size - 16)
        val tag = ciphertextWithTag.copyOfRange(ciphertextWithTag.size - 16, ciphertextWithTag.size)

        val engine = ChaCha7539Engine()
        engine.init(false, ParametersWithIV(KeyParameter(key), nonce))

        // Regenerate Poly1305 key.
        val poly1305Key = ByteArray(64)
        engine.processBytes(poly1305Key, 0, 64, poly1305Key, 0)

        // Verify tag.
        val expectedTag = poly1305Tag(poly1305Key.copyOfRange(0, 32), aad, ciphertext)
        if (!constantTimeEquals(tag, expectedTag)) {
            throw SecurityException("ChaCha20-Poly1305 authentication failed")
        }

        // Decrypt.
        val plaintext = ByteArray(ciphertext.size)
        engine.processBytes(ciphertext, 0, ciphertext.size, plaintext, 0)
        return plaintext
    }

    private fun poly1305Tag(key: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray {
        val mac = Poly1305()
        mac.init(KeyParameter(key))

        // AAD
        mac.update(aad, 0, aad.size)
        pad16(mac, aad.size)

        // Ciphertext
        mac.update(ciphertext, 0, ciphertext.size)
        pad16(mac, ciphertext.size)

        // Lengths (little-endian 8-byte each)
        val lengths = ByteArray(16)
        littleEndian8(aad.size.toLong(), lengths, 0)
        littleEndian8(ciphertext.size.toLong(), lengths, 8)
        mac.update(lengths, 0, 16)

        val out = ByteArray(16)
        mac.doFinal(out, 0)
        return out
    }

    private fun pad16(mac: Poly1305, len: Int) {
        val rem = len % 16
        if (rem != 0) {
            val pad = ByteArray(16 - rem)
            mac.update(pad, 0, pad.size)
        }
    }

    private fun littleEndian8(v: Long, buf: ByteArray, off: Int) {
        for (i in 0..7) buf[off + i] = (v ushr (8 * i)).toByte()
    }

    private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }
}
