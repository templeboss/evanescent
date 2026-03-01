package net.evanescent.db

import androidx.room.*

@Dao
interface SessionDao {
    @Query("SELECT * FROM sessions WHERE contact_id = :contactId LIMIT 1")
    suspend fun get(contactId: ByteArray): SessionEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(session: SessionEntity)

    @Query("DELETE FROM sessions WHERE contact_id = :contactId")
    suspend fun delete(contactId: ByteArray)
}
