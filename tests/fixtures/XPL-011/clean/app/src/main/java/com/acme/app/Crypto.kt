package com.acme.app

import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

object Crypto {
    // Old code used SecretKeySpec("0123456789abcdef".toByteArray(), "AES"); never again.
    fun generated() = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()

    fun random(): SecretKeySpec {
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        return SecretKeySpec(bytes, "AES")
    }

    fun derived(password: CharArray, salt: ByteArray): SecretKeySpec {
        val derivedKey = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            .generateSecret(PBEKeySpec(password, salt, 600_000, 256)).encoded
        return SecretKeySpec(derivedKey, "AES")
    }
}
