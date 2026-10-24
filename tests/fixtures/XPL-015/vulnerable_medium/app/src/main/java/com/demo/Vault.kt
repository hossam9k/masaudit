package com.demo

import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

fun unlockVault(password: String, salt: ByteArray): ByteArray {
    val f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
    return f.generateSecret(PBEKeySpec(password.toCharArray(), salt, 100_000, 256)).encoded
}
