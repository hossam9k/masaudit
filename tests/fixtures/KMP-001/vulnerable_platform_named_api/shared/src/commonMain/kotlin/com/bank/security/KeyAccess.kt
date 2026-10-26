// Shared API named after each platform's mechanism: an expect object, a fun interface, a suspend expect fun, an expect class.
package com.bank.security

expect object KeychainAccess {
    fun read(account: String): String?
    fun write(account: String, value: String)
}

fun interface StrongBoxSigner {
    fun sign(payload: ByteArray): ByteArray
}

expect suspend fun loadSecureEnclaveKey(tag: String): ByteArray?

expect class AndroidKeyStoreCipher(alias: String) {
    fun encrypt(plain: ByteArray): ByteArray
    fun decrypt(cipher: ByteArray): ByteArray
}
