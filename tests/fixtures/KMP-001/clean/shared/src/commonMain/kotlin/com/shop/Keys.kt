package com.shop
// expect fun getKeystoreKey(alias: String): ByteArray   (replaced by SecureTokenStore)
expect suspend fun storeToken(token: String, requiringUserAuth: Boolean)
interface SecureTokenStore {
    suspend fun store(token: String, requireUserPresence: Boolean)
    suspend fun read(): String?
    suspend fun clear()
}
const val SERVICE = "Keychain service name"
