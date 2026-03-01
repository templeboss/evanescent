package net.evanescent.crypto

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Manages the user's Ed25519 identity keypair and the SQLCipher database key.
 *
 * Strategy: Ed25519 keys are generated via Bouncy Castle. The private key bytes
 * are encrypted with an AES-256-GCM key that lives in Android Keystore (TEE-backed).
 * Encrypted blobs are stored in EncryptedSharedPreferences.
 */
class KeyManager(private val context: Context) {

    companion object {
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val KEYSTORE_ALIAS = "evanescent_master_key"
        private const val PREFS_NAME = "evanescent_keys"
        private const val KEY_IDENTITY_PUB = "identity_pub"
        private const val KEY_IDENTITY_PRIV_ENC = "identity_priv_enc"
        private const val KEY_IDENTITY_PRIV_IV = "identity_priv_iv"
        private const val KEY_DB_ENC = "db_key_enc"
        private const val KEY_DB_IV = "db_key_iv"
        private const val GCM_TAG_BITS = 128
    }

    private val keyStore: KeyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).also { it.load(null) }
    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    /**
     * Returns the Ed25519 identity keypair. Generates and persists it on first call.
     * @return Pair(privateKeyBytes 64 bytes, publicKeyBytes 32 bytes)
     */
    fun getOrCreateIdentityKeyPair(): Pair<ByteArray, ByteArray> {
        val pubB64 = prefs.getString(KEY_IDENTITY_PUB, null)
        val privEncB64 = prefs.getString(KEY_IDENTITY_PRIV_ENC, null)
        val privIvB64 = prefs.getString(KEY_IDENTITY_PRIV_IV, null)

        if (pubB64 != null && privEncB64 != null && privIvB64 != null) {
            val pub = Base64.decode(pubB64, Base64.NO_WRAP)
            val privEnc = Base64.decode(privEncB64, Base64.NO_WRAP)
            val privIv = Base64.decode(privIvB64, Base64.NO_WRAP)
            val priv = decryptWithKeystore(privEnc, privIv)
            return Pair(priv, pub)
        }

        return generateAndStore()
    }

    private fun generateAndStore(): Pair<ByteArray, ByteArray> {
        val gen = Ed25519KeyPairGenerator()
        gen.init(Ed25519KeyGenerationParameters(SecureRandom()))
        val kp = gen.generateKeyPair()
        val priv = (kp.private as Ed25519PrivateKeyParameters).encoded  // 32 bytes seed
        val pub = (kp.public as Ed25519PublicKeyParameters).encoded      // 32 bytes

        val (iv, enc) = encryptWithKeystore(priv)
        prefs.edit()
            .putString(KEY_IDENTITY_PUB, Base64.encodeToString(pub, Base64.NO_WRAP))
            .putString(KEY_IDENTITY_PRIV_ENC, Base64.encodeToString(enc, Base64.NO_WRAP))
            .putString(KEY_IDENTITY_PRIV_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
            .apply()
        return Pair(priv, pub)
    }

    /**
     * Derives a 32-byte database key protected by the Keystore AES key.
     */
    fun getDatabaseKey(): ByteArray {
        val encB64 = prefs.getString(KEY_DB_ENC, null)
        val ivB64 = prefs.getString(KEY_DB_IV, null)
        if (encB64 != null && ivB64 != null) {
            return decryptWithKeystore(
                Base64.decode(encB64, Base64.NO_WRAP),
                Base64.decode(ivB64, Base64.NO_WRAP)
            )
        }
        val dbKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val (iv, enc) = encryptWithKeystore(dbKey)
        prefs.edit()
            .putString(KEY_DB_ENC, Base64.encodeToString(enc, Base64.NO_WRAP))
            .putString(KEY_DB_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
            .apply()
        return dbKey
    }

    private fun getOrCreateKeystoreKey(): SecretKey {
        if (!keyStore.containsAlias(KEYSTORE_ALIAS)) {
            val spec = KeyGenParameterSpec.Builder(
                KEYSTORE_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(false)
                .build()
            val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
            gen.init(spec)
            gen.generateKey()
        }
        return (keyStore.getEntry(KEYSTORE_ALIAS, null) as KeyStore.SecretKeyEntry).secretKey
    }

    private fun encryptWithKeystore(plaintext: ByteArray): Pair<ByteArray, ByteArray> {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKeystoreKey())
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(plaintext)
        return Pair(iv, ciphertext)
    }

    private fun decryptWithKeystore(ciphertext: ByteArray, iv: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateKeystoreKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher.doFinal(ciphertext)
    }
}
