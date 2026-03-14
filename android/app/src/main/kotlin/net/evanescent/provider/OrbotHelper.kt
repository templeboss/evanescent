package net.evanescent.provider

/**
 * Deprecated — replaced by [TorManager] (embedded Tor via tor-android).
 * Kept as a thin shim so any remaining references continue to compile
 * until they are individually migrated.
 */
@Deprecated("Use TorManager instead", replaceWith = ReplaceWith("TorManager"))
object OrbotHelper {

    @Deprecated("Use TorManager.isValidOnionAddress()", replaceWith = ReplaceWith("TorManager.isValidOnionAddress(address)"))
    fun isValidOnionAddress(address: String): Boolean =
        TorManager.isValidOnionAddress(address)
}
