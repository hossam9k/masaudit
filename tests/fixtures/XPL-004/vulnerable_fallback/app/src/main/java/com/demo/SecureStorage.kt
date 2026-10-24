package com.demo

import java.security.NoSuchAlgorithmException
import javax.crypto.Cipher

class SecureStorage {
    fun decryptCipher(): Cipher {
        val cipher = try {
            Cipher.getInstance("AES/GCM/NoPadding")
        } catch (e: NoSuchAlgorithmException) {
            Cipher.getInstance("AES/ECB/PKCS5Padding") // Fallback for old devices
        }
        return cipher
    }
}
