package net.evanescent.db

import androidx.room.*
import kotlinx.coroutines.flow.Flow

@Dao
interface ContactDao {
    @Query("SELECT * FROM contacts ORDER BY alias ASC")
    fun getAllFlow(): Flow<List<ContactEntity>>

    @Query("SELECT * FROM contacts WHERE identity_key = :key LIMIT 1")
    suspend fun getByKey(key: ByteArray): ContactEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(contact: ContactEntity)

    @Delete
    suspend fun delete(contact: ContactEntity)

    @Query("UPDATE contacts SET verified = 1 WHERE identity_key = :key")
    suspend fun markVerified(key: ByteArray)
}
