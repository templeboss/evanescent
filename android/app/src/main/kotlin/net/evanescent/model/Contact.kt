package net.evanescent.model

data class Contact(
    val identityKey: ByteArray,       // Ed25519 pubkey, 32 bytes — primary key
    val nymAddress: String,           // Provider's Nym address
    val providerOnion: String,        // Provider's .onion address
    val alias: String,                // Local display name
    val verified: Boolean = false     // Safety number verified
) {
    override fun equals(other: Any?): Boolean {
        if (other !is Contact) return false
        return identityKey.contentEquals(other.identityKey)
    }
    override fun hashCode(): Int = identityKey.contentHashCode()
}
