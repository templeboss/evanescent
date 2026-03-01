package net.evanescent.crypto

import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.junit.Assert.*
import org.junit.Test
import java.security.SecureRandom

class DoubleRatchetTest {

    private fun sharedSecret() = ByteArray(32).also { SecureRandom().nextBytes(it) }

    private fun generateX25519(): Pair<ByteArray, ByteArray> {
        val priv = X25519PrivateKeyParameters(SecureRandom())
        return Pair(priv.encoded, priv.generatePublicKey().encoded)
    }

    @Test
    fun `basic encrypt decrypt round trip`() {
        val ms = sharedSecret()
        val (bobSpkPriv, bobSpkPub) = generateX25519()

        val aliceState = DoubleRatchet.initAlice(ms, bobSpkPub)
        val bobState = DoubleRatchet.initBob(ms, bobSpkPriv, bobSpkPub)

        val plaintext = "Hello, World!".toByteArray(Charsets.UTF_8)
        val (aliceState2, drMsgBytes) = DoubleRatchet.encrypt(aliceState, plaintext)

        val (_, decrypted) = DoubleRatchet.decrypt(bobState, drMsgBytes)
        assertArrayEquals("Decrypted must equal original", plaintext, decrypted)
    }

    @Test
    fun `multiple messages in sequence`() {
        val ms = sharedSecret()
        val (bobSpkPriv, bobSpkPub) = generateX25519()

        var aliceState = DoubleRatchet.initAlice(ms, bobSpkPub)
        var bobState = DoubleRatchet.initBob(ms, bobSpkPriv, bobSpkPub)

        val messages = listOf("msg1", "msg2", "msg3", "msg4", "msg5")
        for (msg in messages) {
            val plain = msg.toByteArray()
            val (newAlice, drBytes) = DoubleRatchet.encrypt(aliceState, plain)
            aliceState = newAlice
            val (newBob, decrypted) = DoubleRatchet.decrypt(bobState, drBytes)
            bobState = newBob
            assertArrayEquals("Message '$msg' must round-trip", plain, decrypted)
        }
    }

    @Test
    fun `out of order delivery`() {
        val ms = sharedSecret()
        val (bobSpkPriv, bobSpkPub) = generateX25519()

        var aliceState = DoubleRatchet.initAlice(ms, bobSpkPub)
        var bobState = DoubleRatchet.initBob(ms, bobSpkPriv, bobSpkPub)

        val plain1 = "first".toByteArray()
        val plain2 = "second".toByteArray()

        val (aliceState2, dr1) = DoubleRatchet.encrypt(aliceState, plain1)
        val (aliceState3, dr2) = DoubleRatchet.encrypt(aliceState2, plain2)

        // Deliver second message first.
        val (bobState2, dec2) = DoubleRatchet.decrypt(bobState, dr2)
        assertArrayEquals("Second message must decrypt", plain2, dec2)

        // Now deliver first message (was skipped).
        val (_, dec1) = DoubleRatchet.decrypt(bobState2, dr1)
        assertArrayEquals("First message must decrypt from skip list", plain1, dec1)
    }
}
