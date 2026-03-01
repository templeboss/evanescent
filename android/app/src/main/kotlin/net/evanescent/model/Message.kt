package net.evanescent.model

data class Message(
    val id: String,                    // UUID v4
    val contactId: ByteArray,          // Identity key of the contact
    val direction: MessageDirection,
    val plaintext: String,
    val timestamp: Long,               // Unix milliseconds
    val status: MessageStatus
) {
    override fun equals(other: Any?): Boolean {
        if (other !is Message) return false
        return id == other.id
    }
    override fun hashCode(): Int = id.hashCode()
}
