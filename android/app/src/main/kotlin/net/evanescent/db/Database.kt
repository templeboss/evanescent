package net.evanescent.db

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import net.sqlcipher.database.SupportFactory

@Database(
    entities = [ContactEntity::class, SessionEntity::class, MessageEntity::class, PreKeyEntity::class],
    version = 2,
    exportSchema = false
)
abstract class AppDatabase : RoomDatabase() {
    abstract fun contactDao(): ContactDao
    abstract fun sessionDao(): SessionDao
    abstract fun messageDao(): MessageDao
    abstract fun preKeyDao(): PreKeyDao

    companion object {
        @Volatile private var instance: AppDatabase? = null

        private val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(database: SupportSQLiteDatabase) {
                // Add nullable mailbox_addr column for shared-provider routing tag.
                database.execSQL("ALTER TABLE contacts ADD COLUMN mailbox_addr BLOB")
            }
        }

        fun getInstance(context: Context, dbKeyBytes: ByteArray): AppDatabase {
            return instance ?: synchronized(this) {
                instance ?: buildDatabase(context, dbKeyBytes).also { instance = it }
            }
        }

        private fun buildDatabase(context: Context, dbKeyBytes: ByteArray): AppDatabase {
            val factory = SupportFactory(dbKeyBytes)
            return Room.databaseBuilder(context, AppDatabase::class.java, "evanescent.db")
                .openHelperFactory(factory)
                .addMigrations(MIGRATION_1_2)
                .build()
        }
    }
}
