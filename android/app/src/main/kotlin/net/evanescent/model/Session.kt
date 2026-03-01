package net.evanescent.model

import net.evanescent.crypto.RatchetState

data class Session(
    val contactId: ByteArray,     // Identity key of the contact
    val ratchetState: RatchetState
) {
    override fun equals(other: Any?): Boolean {
        if (other !is Session) return false
        return contactId.contentEquals(other.contactId)
    }
    override fun hashCode(): Int = contactId.contentHashCode()
}
