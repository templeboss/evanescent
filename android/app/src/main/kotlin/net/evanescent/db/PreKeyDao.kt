package net.evanescent.db

import androidx.room.*

@Dao
interface PreKeyDao {
    @Query("SELECT COUNT(*) FROM prekeys WHERE type = 'ONE_TIME' AND used = 0")
    suspend fun unusedOneTimeCount(): Int

    @Query("SELECT * FROM prekeys WHERE type = 'ONE_TIME' AND used = 0 ORDER BY prekey_id ASC LIMIT 1")
    suspend fun popOneTime(): PreKeyEntity?

    @Query("UPDATE prekeys SET used = 1 WHERE rowId = :rowId")
    suspend fun markUsed(rowId: Long)

    @Query("SELECT * FROM prekeys WHERE type = 'SIGNED' ORDER BY prekey_id DESC LIMIT 1")
    suspend fun getLatestSigned(): PreKeyEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(key: PreKeyEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAll(keys: List<PreKeyEntity>)

    @Query("SELECT MAX(prekey_id) FROM prekeys")
    suspend fun maxPrekeyId(): Int?

    @Query("SELECT * FROM prekeys WHERE type = :type AND prekey_id = :id LIMIT 1")
    suspend fun getByIdAndType(id: Int, type: String): PreKeyEntity?
}
