package net.evanescent.db

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import net.sqlcipher.database.SupportFactory

@Database(
    entities = [ContactEntity::class, SessionEntity::class, MessageEntity::class, PreKeyEntity::class],
    version = 1,
    exportSchema = false
)
abstract class AppDatabase : RoomDatabase() {
    abstract fun contactDao(): ContactDao
    abstract fun sessionDao(): SessionDao
    abstract fun messageDao(): MessageDao
    abstract fun preKeyDao(): PreKeyDao

    companion object {
        @Volatile private var instance: AppDatabase? = null

        fun getInstance(context: Context, dbKeyBytes: ByteArray): AppDatabase {
            return instance ?: synchronized(this) {
                instance ?: buildDatabase(context, dbKeyBytes).also { instance = it }
            }
        }

        private fun buildDatabase(context: Context, dbKeyBytes: ByteArray): AppDatabase {
            val factory = SupportFactory(dbKeyBytes)
            return Room.databaseBuilder(context, AppDatabase::class.java, "evanescent.db")
                .openHelperFactory(factory)
                .build()
        }
    }
}
