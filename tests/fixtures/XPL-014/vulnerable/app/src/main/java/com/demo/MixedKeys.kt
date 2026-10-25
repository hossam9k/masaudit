package com.demo

import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.SecureRandom
import javax.crypto.KeyGenerator

class MixedKeys {
    fun generate() {
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA)
        generator.initialize(1024, SecureRandom())
        val keypair = generator.genKeyPair()

        val keyGen = KeyGenerator.getInstance("AES")
        keyGen.init(256)
        val secretKey = keyGen.generateKey()
    }
}
