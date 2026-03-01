package net.evanescent.crypto

import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.junit.Assert.*
import org.junit.Test
import java.security.SecureRandom

class X3DHTest {

    private fun genEd25519(): Pair<ByteArray, ByteArray> {
        val gen = Ed25519KeyPairGenerator()
        gen.init(Ed25519KeyGenerationParameters(SecureRandom()))
        val kp = gen.generateKeyPair()
        val priv = (kp.private as Ed25519PrivateKeyParameters).encoded
        val pub = (kp.public as Ed25519PublicKeyParameters).encoded
        return Pair(priv, pub)
    }

    private fun genX25519(): Pair<ByteArray, ByteArray> {
        val priv = X25519PrivateKeyParameters(SecureRandom())
        return Pair(priv.encoded, priv.generatePublicKey().encoded)
    }

    @Test
    fun `alice and bob derive the same master secret`() {
        val (alicePriv, alicePub) = genEd25519()
        val (bobPriv, bobPub) = genEd25519()
        val (bobSpkPriv, bobSpkPub) = genX25519()
        val (bobOpkPriv, bobOpkPub) = genX25519()

        val bobSpkSig = X3DH.signPreKey(bobPriv, bobSpkPub)
        assertTrue("SPK signature must verify", X3DH.verifyPreKey(bobPub, bobSpkPub, bobSpkSig))

        val bundle = PreKeyBundle(
            identityKey = bobPub,
            signedPrekeyId = 1,
            signedPrekey = bobSpkPub,
            signedPrekeySig = bobSpkSig,
            oneTimePrekeyId = 1,
            oneTimePrekey = bobOpkPub
        )

        val result = X3DH.initiate(alicePriv, alicePub, bundle)

        val bobMasterSecret = X3DH.respond(
            bobIdentityPriv = bobPriv,
            bobSpkPriv = bobSpkPriv,
            bobOpkPriv = bobOpkPriv,
            aliceIdentityPub = alicePub,
            aliceEphemeralPub = result.ephemeralPublic
        )

        assertArrayEquals("Alice and Bob must derive the same master secret", result.masterSecret, bobMasterSecret)
    }

    @Test
    fun `master secret differs without OPK`() {
        val (alicePriv, alicePub) = genEd25519()
        val (bobPriv, bobPub) = genEd25519()
        val (bobSpkPriv, bobSpkPub) = genX25519()
        val (bobOpkPriv, bobOpkPub) = genX25519()
        val bobSpkSig = X3DH.signPreKey(bobPriv, bobSpkPub)

        // With OPK
        val bundleWith = PreKeyBundle(bobPub, 1, bobSpkPub, bobSpkSig, 1, bobOpkPub)
        val resultWith = X3DH.initiate(alicePriv, alicePub, bundleWith)
        val bobWith = X3DH.respond(bobPriv, bobSpkPriv, bobOpkPriv, alicePub, resultWith.ephemeralPublic)
        assertArrayEquals(resultWith.masterSecret, bobWith)

        // Without OPK
        val bundleWithout = PreKeyBundle(bobPub, 1, bobSpkPub, bobSpkSig)
        val resultWithout = X3DH.initiate(alicePriv, alicePub, bundleWithout)
        val bobWithout = X3DH.respond(bobPriv, bobSpkPriv, null, alicePub, resultWithout.ephemeralPublic)
        assertArrayEquals(resultWithout.masterSecret, bobWithout)

        // Secrets differ
        assertFalse("With and without OPK secrets must differ",
            resultWith.masterSecret.contentEquals(resultWithout.masterSecret))
    }

    @Test
    fun `SPK signature verification`() {
        val (identityPriv, identityPub) = genEd25519()
        val (_, spkPub) = genX25519()

        val sig = X3DH.signPreKey(identityPriv, spkPub)
        assertTrue("Valid signature must verify", X3DH.verifyPreKey(identityPub, spkPub, sig))

        val tampered = sig.copyOf()
        tampered[0] = tampered[0].xor(0xFF.toByte())
        assertFalse("Tampered signature must not verify", X3DH.verifyPreKey(identityPub, spkPub, tampered))
    }
}
