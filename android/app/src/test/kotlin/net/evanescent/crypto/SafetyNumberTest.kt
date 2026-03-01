package net.evanescent.crypto

import org.junit.Assert.*
import org.junit.Test
import java.security.SecureRandom

class SafetyNumberTest {

    @Test
    fun `same keys produce same number regardless of call order`() {
        val keyA = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val keyB = ByteArray(32).also { SecureRandom().nextBytes(it) }

        val sn1 = SafetyNumber.compute(keyA, keyB)
        val sn2 = SafetyNumber.compute(keyB, keyA)

        assertEquals("Safety number must be commutative", sn1, sn2)
    }

    @Test
    fun `different keys produce different numbers`() {
        val keyA = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val keyB = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val keyC = ByteArray(32).also { SecureRandom().nextBytes(it) }

        val sn1 = SafetyNumber.compute(keyA, keyB)
        val sn2 = SafetyNumber.compute(keyA, keyC)

        assertNotEquals("Different key pairs must produce different safety numbers", sn1, sn2)
    }

    @Test
    fun `output format is 5 groups of 6 digits`() {
        val keyA = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val keyB = ByteArray(32).also { SecureRandom().nextBytes(it) }

        val sn = SafetyNumber.compute(keyA, keyB)
        val groups = sn.split(" ")

        assertEquals("Must have 5 groups", 5, groups.size)
        groups.forEach { group ->
            assertEquals("Each group must be 6 digits", 6, group.length)
            assertTrue("Each group must be all digits", group.all { it.isDigit() })
        }
    }

    @Test
    fun `deterministic for fixed inputs`() {
        val keyA = ByteArray(32) { it.toByte() }
        val keyB = ByteArray(32) { (it + 32).toByte() }

        val sn1 = SafetyNumber.compute(keyA, keyB)
        val sn2 = SafetyNumber.compute(keyA, keyB)

        assertEquals("Must be deterministic", sn1, sn2)
    }
}
