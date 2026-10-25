package com.example.bank

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties

class Keys {
    private val validity = 60 * 60 * 24

    fun spec(alias: String): KeyGenParameterSpec =
        KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(86400, KeyProperties.AUTH_BIOMETRIC_STRONG)
            .build()

    fun legacySpec(alias: String): KeyGenParameterSpec =
        KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationValidityDurationSeconds(60 * 60 * 24)
            .build()

    fun constSpec(alias: String): KeyGenParameterSpec =
        KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationValidityDurationSeconds(UNLOCK_WINDOW)
            .build()

    companion object {
        const val UNLOCK_WINDOW = 3600
    }
}
