package net.evanescent.crypto

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * X3DH key agreement per the Signal specification and standards.md §2.
 *
 * DH concatenation order (with OPK):
 *   DH(IK'_A, SPK_B) || DH(EK_A, IK'_B) || DH(EK_A, SPK_B) || DH(EK_A, OPK_B)
 *
 * Without OPK:
 *   DH(IK'_A, SPK_B) || DH(EK_A, IK'_B) || DH(EK_A, SPK_B)
 *
 * HKDF: F(32 x 0xFF) || DH_result, salt=0x00*32, info="Evanescent_X3DH_v1" → 32 bytes
 */
object X3DH {

    private val F = ByteArray(32) { 0xFF.toByte() }
    private val ZERO_SALT = ByteArray(32)

    /**
     * Alice initiates: computes the shared master secret from Bob's prekey bundle.
     *
     * @param aliceIdentityPriv  Alice's Ed25519 private key (seed, 32 bytes)
     * @param aliceIdentityPub   Alice's Ed25519 public key (32 bytes)
     * @param bobBundle          Bob's prekey bundle
     * @return X3DHResult containing master secret and ephemeral public key (to send to Bob)
     */
    fun initiate(
        aliceIdentityPriv: ByteArray,
        aliceIdentityPub: ByteArray,
        bobBundle: PreKeyBundle
    ): X3DHResult {
        // Convert Alice's Ed25519 identity key to X25519 for DH operations.
        val aliceIkX = ed25519ToX25519Priv(aliceIdentityPriv)

        // Generate fresh ephemeral X25519 keypair.
        val ekPriv = X25519PrivateKeyParameters(SecureRandom())
        val ekPub = ekPriv.generatePublicKey()

        // Convert Bob's Ed25519 identity key to X25519 (Montgomery form).
        val bobIkX = ed25519PubToX25519Pub(bobBundle.identityKey)

        val bobSpkPub = X25519PublicKeyParameters(bobBundle.signedPrekey, 0)

        val dh1 = dh(aliceIkX, bobSpkPub)           // DH(IK'_A, SPK_B)
        val dh2 = dh(ekPriv, bobIkX)                 // DH(EK_A, IK'_B)
        val dh3 = dh(ekPriv, bobSpkPub)              // DH(EK_A, SPK_B)

        val dhInput = if (bobBundle.oneTimePrekey != null) {
            val bobOpkPub = X25519PublicKeyParameters(bobBundle.oneTimePrekey, 0)
            val dh4 = dh(ekPriv, bobOpkPub)           // DH(EK_A, OPK_B)
            dh1 + dh2 + dh3 + dh4
        } else {
            dh1 + dh2 + dh3
        }

        val masterSecret = deriveSecret(dhInput)
        return X3DHResult(
            masterSecret = masterSecret,
            ephemeralPublic = ekPub.encoded,
            usedOneTimePrekey = bobBundle.oneTimePrekey != null,
            oneTimePrekeyId = bobBundle.oneTimePrekeyId
        )
    }

    /**
     * Bob responds: computes the shared master secret from Alice's initial message.
     *
     * @param bobIdentityPriv    Bob's Ed25519 private key (seed)
     * @param bobIdentityPub     Bob's Ed25519 public key
     * @param bobSpkPriv         Bob's signed prekey private key (X25519)
     * @param bobOpkPriv         Bob's one-time prekey private key (X25519), or null
     * @param aliceIdentityPub   Alice's Ed25519 public key (from SealedSenderContent)
     * @param aliceEphemeralPub  Alice's ephemeral X25519 public key
     */
    fun respond(
        bobIdentityPriv: ByteArray,
        bobSpkPriv: ByteArray,
        bobOpkPriv: ByteArray?,
        aliceIdentityPub: ByteArray,
        aliceEphemeralPub: ByteArray
    ): ByteArray {
        val bobIkX = ed25519ToX25519Priv(bobIdentityPriv)
        val bobSpk = X25519PrivateKeyParameters(bobSpkPriv, 0)
        val aliceIkX = ed25519PubToX25519Pub(aliceIdentityPub)
        val aliceEk = X25519PublicKeyParameters(aliceEphemeralPub, 0)

        val dh1 = dh(bobSpk, aliceIkX)              // DH(SPK_B, IK'_A)  = DH(IK'_A, SPK_B)
        val dh2 = dh(bobIkX, aliceEk)               // DH(IK'_B, EK_A)
        val dh3 = dh(bobSpk, aliceEk)               // DH(SPK_B, EK_A)

        val dhInput = if (bobOpkPriv != null) {
            val bobOpk = X25519PrivateKeyParameters(bobOpkPriv, 0)
            val dh4 = dh(bobOpk, aliceEk)
            dh1 + dh2 + dh3 + dh4
        } else {
            dh1 + dh2 + dh3
        }

        return deriveSecret(dhInput)
    }

    /**
     * Signs a signed prekey per standards.md §2.
     * message = "Evanescent_SPK_v1" || spk_public_bytes
     */
    fun signPreKey(identityPriv: ByteArray, spkPublic: ByteArray): ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, Ed25519PrivateKeyParameters(identityPriv, 0))
        val msg = Hkdf.INFO_SPK.toByteArray(Charsets.UTF_8) + spkPublic
        signer.update(msg, 0, msg.size)
        return signer.generateSignature()
    }

    /**
     * Verifies a signed prekey signature.
     */
    fun verifyPreKey(identityPub: ByteArray, spkPublic: ByteArray, signature: ByteArray): Boolean {
        val verifier = Ed25519Signer()
        verifier.init(false, Ed25519PublicKeyParameters(identityPub, 0))
        val msg = Hkdf.INFO_SPK.toByteArray(Charsets.UTF_8) + spkPublic
        verifier.update(msg, 0, msg.size)
        return verifier.verifySignature(signature)
    }

    private fun deriveSecret(dhOutput: ByteArray): ByteArray {
        val ikm = F + dhOutput
        return Hkdf.expand(ikm, ZERO_SALT, Hkdf.INFO_X3DH, 32)
    }

    private fun dh(priv: X25519PrivateKeyParameters, pub: X25519PublicKeyParameters): ByteArray {
        val agreement = X25519Agreement()
        agreement.init(priv)
        val out = ByteArray(32)
        agreement.calculateAgreement(pub, out, 0)
        return out
    }

    /**
     * Converts an Ed25519 private key seed to an X25519 private key.
     * Per RFC 8032 §5.1.5: SHA-512 the seed, clamp bytes [0:32].
     */
    fun ed25519ToX25519Priv(ed25519Seed: ByteArray): X25519PrivateKeyParameters {
        val hash = MessageDigest.getInstance("SHA-512").digest(ed25519Seed)
        // Clamp per RFC 8032
        hash[0] = (hash[0].toInt() and 248).toByte()
        hash[31] = (hash[31].toInt() and 127).toByte()
        hash[31] = (hash[31].toInt() or 64).toByte()
        return X25519PrivateKeyParameters(hash, 0)
    }

    /**
     * Converts an Ed25519 public key to X25519 (Montgomery form).
     * Uses Bouncy Castle's internal conversion.
     */
    fun ed25519PubToX25519Pub(ed25519Pub: ByteArray): X25519PublicKeyParameters {
        val edPub = Ed25519PublicKeyParameters(ed25519Pub, 0)
        // Bouncy Castle provides this conversion.
        return edPub.generatePublicKey() as X25519PublicKeyParameters
    }
}

data class PreKeyBundle(
    val identityKey: ByteArray,
    val signedPrekeyId: Int,
    val signedPrekey: ByteArray,
    val signedPrekeySig: ByteArray,
    val oneTimePrekeyId: Int = 0,
    val oneTimePrekey: ByteArray? = null
)

data class X3DHResult(
    val masterSecret: ByteArray,
    val ephemeralPublic: ByteArray,
    val usedOneTimePrekey: Boolean,
    val oneTimePrekeyId: Int
)

private operator fun ByteArray.plus(other: ByteArray): ByteArray {
    val result = ByteArray(size + other.size)
    System.arraycopy(this, 0, result, 0, size)
    System.arraycopy(other, 0, result, size, other.size)
    return result
}
