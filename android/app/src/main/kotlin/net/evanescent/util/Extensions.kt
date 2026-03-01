package net.evanescent.util

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

fun String.fromHex(): ByteArray {
    val len = length
    require(len % 2 == 0) { "hex string must have even length" }
    return ByteArray(len / 2) { i ->
        substring(2 * i, 2 * i + 2).toInt(16).toByte()
    }
}
