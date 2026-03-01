package net.evanescent.crypto

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters

/**
 * HKDF-SHA256 utility. Thin wrapper around Bouncy Castle.
 * All info strings are defined as constants below per standards.md.
 */
object Hkdf {

    // HKDF info strings — must match exactly across Go and Android.
    const val INFO_X3DH = "Evanescent_X3DH_v1"
    const val INFO_SPK = "Evanescent_SPK_v1"
    const val INFO_AUTH = "Evanescent_Auth_v1"
    const val INFO_DB = "Evanescent_DB_v1"
    const val INFO_SEALED_SENDER = "Evanescent_SealedSender_v1"
    const val INFO_DR_RK = "Evanescent_DR_RK_v1"

    private val ZERO_SALT_32 = ByteArray(32)

    /**
     * Derive [length] bytes from [ikm] using HKDF-SHA256 with the given [salt] and [info].
     */
    fun expand(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(HKDFParameters(ikm, salt, info))
        val output = ByteArray(length)
        hkdf.generateBytes(output, 0, length)
        return output
    }

    fun expand(ikm: ByteArray, info: String, length: Int): ByteArray =
        expand(ikm, ZERO_SALT_32, info.toByteArray(Charsets.UTF_8), length)

    fun expand(ikm: ByteArray, salt: ByteArray, info: String, length: Int): ByteArray =
        expand(ikm, salt, info.toByteArray(Charsets.UTF_8), length)
}
