package com.demo

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import javax.crypto.Cipher

class BiometricsEncryptionManager {
    private val spec: KeyGenParameterSpec
        get() = KeyGenParameterSpec
            .Builder("biometric_integrity", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .build()

    fun cipher(): Cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
}
