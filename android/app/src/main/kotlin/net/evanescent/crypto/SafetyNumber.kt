package net.evanescent.crypto

import java.security.MessageDigest

/**
 * Safety number computation per standards.md §8.
 *
 * safety_number = SHA256(sort(IK_A, IK_B) concatenated)[0:30]
 * Display: 5 groups of 6 decimal digits
 */
object SafetyNumber {

    /**
     * Compute a 30-digit safety number string for two identity keys.
     * Both parties must call with the same two keys to get the same result.
     */
    fun compute(keyA: ByteArray, keyB: ByteArray): String {
        require(keyA.size == 32) { "keyA must be 32 bytes" }
        require(keyB.size == 32) { "keyB must be 32 bytes" }

        // Sort lexicographically so both parties get the same result.
        val (first, second) = if (keyA.lexicographicCompareTo(keyB) <= 0) {
            Pair(keyA, keyB)
        } else {
            Pair(keyB, keyA)
        }

        val combined = first + second
        val hash = MessageDigest.getInstance("SHA-256").digest(combined)

        // Take first 30 bytes, convert each to 2-digit decimal (0-255 → 00-99 via modulo).
        // Signal uses 5 groups of 6 decimal digits = 30 digits total.
        // Map each byte to 0-9 with hash[i] % 10, producing 30 single digits.
        // Then chunk into 5 groups of 6.
        val digits = hash.take(30).joinToString("") { byte ->
            ((byte.toInt() and 0xFF) % 10).toString()
        }
        return digits.chunked(6).joinToString(" ")
    }

    private fun ByteArray.lexicographicCompareTo(other: ByteArray): Int {
        val len = minOf(size, other.size)
        for (i in 0 until len) {
            val diff = (this[i].toInt() and 0xFF) - (other[i].toInt() and 0xFF)
            if (diff != 0) return diff
        }
        return size - other.size
    }
}

private operator fun ByteArray.plus(other: ByteArray): ByteArray {
    val result = ByteArray(size + other.size)
    System.arraycopy(this, 0, result, 0, size)
    System.arraycopy(other, 0, result, size, other.size)
    return result
}
