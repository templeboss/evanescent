package net.evanescent.crypto

import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.junit.Assert.*
import org.junit.Test
import java.security.SecureRandom

class SealedSenderTest {

    private fun generateEd25519KeyPair(): Pair<ByteArray, ByteArray> {
        val gen = Ed25519KeyPairGenerator()
        gen.init(Ed25519KeyGenerationParameters(SecureRandom()))
        val kp = gen.generateKeyPair()
        val priv = (kp.private as Ed25519PrivateKeyParameters).encoded
        val pub = (kp.public as Ed25519PublicKeyParameters).encoded
        return Pair(priv, pub)
    }

    @Test
    fun `round trip seal and unseal`() {
        val (alicePriv, alicePub) = generateEd25519KeyPair()
        val (bobPriv, bobPub) = generateEd25519KeyPair()

        val drMessage = "Hello, Bob!".toByteArray(Charsets.UTF_8)
        val senderNymAddr = "alice@gateway1"

        val envelope = SealedSender.seal(
            drMessageBytes = drMessage,
            recipientIdentityKey = bobPub,
            senderIdentityKey = alicePub,
            senderNymAddress = senderNymAddr
        )

        val (senderKey, nymAddr, decrypted) = SealedSender.unseal(envelope, bobPriv)

        assertArrayEquals("Sender identity key must match", alicePub, senderKey)
        assertEquals("Nym address must match", senderNymAddr, nymAddr)
        assertArrayEquals("Decrypted content must match", drMessage, decrypted)
    }

    @Test(expected = SecurityException::class)
    fun `tampered ciphertext fails authentication`() {
        val (_, alicePub) = generateEd25519KeyPair()
        val (bobPriv, bobPub) = generateEd25519KeyPair()

        val envelope = SealedSender.seal(
            drMessageBytes = "test".toByteArray(),
            recipientIdentityKey = bobPub,
            senderIdentityKey = alicePub,
            senderNymAddress = "test@gw"
        )

        // Flip a byte in the ciphertext region.
        val tampered = envelope.copyOf()
        tampered[tampered.size - 1] = tampered[tampered.size - 1].xor(0xFF.toByte())

        SealedSender.unseal(tampered, bobPriv)
    }

    @Test(expected = Exception::class)
    fun `wrong recipient key fails`() {
        val (_, alicePub) = generateEd25519KeyPair()
        val (_, bobPub) = generateEd25519KeyPair()
        val (evePriv, _) = generateEd25519KeyPair()

        val envelope = SealedSender.seal(
            drMessageBytes = "secret".toByteArray(),
            recipientIdentityKey = bobPub,
            senderIdentityKey = alicePub,
            senderNymAddress = "test@gw"
        )

        SealedSender.unseal(envelope, evePriv) // Wrong key — must fail
    }
}
