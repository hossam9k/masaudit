package com.demo

import java.security.KeyPairGenerator

class MixedKeys {
    // The RSA key is imported from the server; only the EC pair is made here.
    private val serverAlgorithm = "RSA"

    fun generate(): String {
        val ec = KeyPairGenerator.getInstance("EC")
        ec.initialize(256)
        val pair = ec.genKeyPair()
        return serverAlgorithm + pair.public
    }
}
