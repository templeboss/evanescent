package net.evanescent.provider

import android.util.Log
import net.evanescent.crypto.PreKeyGenerator
import net.evanescent.db.PreKeyDao
import net.evanescent.db.PreKeyEntity

private const val TAG = "Evanescent"
private const val REPLENISH_THRESHOLD = 20
private const val INITIAL_BATCH = 100
private const val REPLENISH_BATCH = 50

/**
 * Watches the local one-time prekey count and triggers uploads when it drops below the threshold.
 */
class PreKeyUploader(
    private val preKeyDao: PreKeyDao,
    private val generator: PreKeyGenerator,
    private val uploadKeys: suspend (signedPreKeys: List<PreKeyEntity>, oneTimePreKeys: List<PreKeyEntity>) -> Unit
) {

    /**
     * Check if prekeys need to be uploaded and do so if needed.
     * Should be called after authentication.
     */
    suspend fun checkAndUpload() {
        val count = preKeyDao.unusedOneTimeCount()
        val spk = preKeyDao.getLatestSigned()

        val signedToUpload = mutableListOf<PreKeyEntity>()
        val oneTimeToUpload = mutableListOf<PreKeyEntity>()

        if (spk == null) {
            // First run — generate initial SPK.
            val nextId = (preKeyDao.maxPrekeyId() ?: 0) + 1
            val gen = generator.generateSignedPreKey(nextId)
            val entity = PreKeyEntity(
                type = "SIGNED",
                prekeyId = gen.id,
                publicKey = gen.publicKey,
                privateKey = gen.privateKey,
                signature = gen.signature
            )
            preKeyDao.insert(entity)
            signedToUpload.add(entity)
        }

        if (count < REPLENISH_THRESHOLD) {
            val batch = if (count == 0) INITIAL_BATCH else REPLENISH_BATCH
            val startId = (preKeyDao.maxPrekeyId() ?: 0) + 1
            val generated = generator.generateOneTimePreKeys(startId, batch)
            val entities = generated.map {
                PreKeyEntity(
                    type = "ONE_TIME",
                    prekeyId = it.id,
                    publicKey = it.publicKey,
                    privateKey = it.privateKey
                )
            }
            preKeyDao.insertAll(entities)
            oneTimeToUpload.addAll(entities)
            Log.d(TAG, "PreKeyUploader: uploading ${entities.size} OTPKs")
        }

        if (signedToUpload.isNotEmpty() || oneTimeToUpload.isNotEmpty()) {
            uploadKeys(signedToUpload, oneTimeToUpload)
        }
    }
}
