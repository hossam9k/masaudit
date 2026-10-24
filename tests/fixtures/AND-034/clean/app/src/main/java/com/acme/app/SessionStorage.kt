package com.acme.app

import androidx.datastore.preferences.core.stringPreferencesKey
import com.google.crypto.tink.Aead

private const val SESSION_TOKEN_KEY = "session_token"

// The value is sealed with a Keystore-backed Tink AEAD before it reaches DataStore.
class SessionStorage(private val aead: Aead) {
    private val key = stringPreferencesKey(SESSION_TOKEN_KEY)

    fun seal(token: String): ByteArray = aead.encrypt(token.toByteArray(), SESSION_TOKEN_KEY.toByteArray())
}
