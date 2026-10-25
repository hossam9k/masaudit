package com.demo

import java.security.SecureRandom
import java.util.Random

class Tokens {
    private val spoilerRandom = Random(System.currentTimeMillis())

    fun make(): Map<String, Long> {
        val tokenExpiry = System.currentTimeMillis() + 3_600_000
        val tokenCreatedAt = System.currentTimeMillis()
        val nonce = System.currentTimeMillis() xor SecureRandom().nextLong()
        val requestStart = System.nanoTime()
        return mapOf("expiry" to tokenExpiry, "created" to tokenCreatedAt, "nonce" to nonce, "start" to requestStart)
    }
}
