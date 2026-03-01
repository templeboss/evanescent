package net.evanescent.db

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "contacts")
data class ContactEntity(
    @PrimaryKey
    @ColumnInfo(name = "identity_key", typeAffinity = androidx.room.ColumnInfo.BLOB)
    val identityKey: ByteArray,
    @ColumnInfo(name = "nym_address") val nymAddress: String,
    @ColumnInfo(name = "provider_onion") val providerOnion: String,
    val alias: String,
    val verified: Int = 0  // 0 = false, 1 = true
) {
    override fun equals(other: Any?): Boolean {
        if (other !is ContactEntity) return false
        return identityKey.contentEquals(other.identityKey)
    }
    override fun hashCode(): Int = identityKey.contentHashCode()
}

@Entity(tableName = "sessions")
data class SessionEntity(
    @PrimaryKey
    @ColumnInfo(name = "contact_id", typeAffinity = androidx.room.ColumnInfo.BLOB)
    val contactId: ByteArray,
    @ColumnInfo(name = "ratchet_state", typeAffinity = androidx.room.ColumnInfo.BLOB)
    val ratchetState: ByteArray  // serialised RatchetState proto bytes
) {
    override fun equals(other: Any?): Boolean {
        if (other !is SessionEntity) return false
        return contactId.contentEquals(other.contactId)
    }
    override fun hashCode(): Int = contactId.contentHashCode()
}

@Entity(tableName = "messages")
data class MessageEntity(
    @PrimaryKey val id: String,
    @ColumnInfo(name = "contact_id", typeAffinity = androidx.room.ColumnInfo.BLOB)
    val contactId: ByteArray,
    val direction: String,   // "INBOUND" or "OUTBOUND"
    val plaintext: String,
    val timestamp: Long,
    val status: String       // MessageStatus name
) {
    override fun equals(other: Any?): Boolean = id == (other as? MessageEntity)?.id
    override fun hashCode(): Int = id.hashCode()
}

@Entity(tableName = "prekeys")
data class PreKeyEntity(
    @PrimaryKey(autoGenerate = true) val rowId: Long = 0,
    val type: String,        // "SIGNED" or "ONE_TIME"
    @ColumnInfo(name = "prekey_id") val prekeyId: Int,
    @ColumnInfo(name = "public_key", typeAffinity = androidx.room.ColumnInfo.BLOB)
    val publicKey: ByteArray,
    @ColumnInfo(name = "private_key", typeAffinity = androidx.room.ColumnInfo.BLOB)
    val privateKey: ByteArray,
    val signature: ByteArray? = null,  // only for SIGNED type
    val used: Int = 0
) {
    override fun equals(other: Any?): Boolean {
        if (other !is PreKeyEntity) return false
        return type == other.type && prekeyId == other.prekeyId
    }
    override fun hashCode(): Int = 31 * type.hashCode() + prekeyId
}
