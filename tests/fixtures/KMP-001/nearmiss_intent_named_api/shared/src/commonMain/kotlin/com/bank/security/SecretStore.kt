// Intent-named shared API; mechanism words appear only in members, errors, config, and docs.
package com.bank.security

/** Backed by the Android Keystore and the iOS Keychain. */
interface SecretStore {
    suspend fun put(name: String, value: ByteArray, requireUserPresence: Boolean)
    suspend fun get(name: String): ByteArray?
    suspend fun migrateFromLegacyKeychain()
}

expect class PlatformSigner(keyName: String) {
    fun sign(payload: ByteArray): ByteArray
}

data class KeychainConfig(val service: String, val accessGroup: String?)

class KeystoreUnavailableException(message: String) : Exception(message)

sealed interface StoreError {
    object KeychainLocked : StoreError
    object StrongBoxMissing : StoreError
}
