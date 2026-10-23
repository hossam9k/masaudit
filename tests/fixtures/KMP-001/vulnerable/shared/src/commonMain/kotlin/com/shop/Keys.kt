package com.shop
expect fun getKeystoreKey(alias: String): ByteArray
interface KeychainHelper {
    fun save(key: String, value: String)
}
expect class SecureEnclaveSigner {
    fun sign(data: ByteArray): ByteArray
}
