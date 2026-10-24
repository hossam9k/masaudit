package com.demo
import kotlin.random.Random
val resetToken = (1..32).map { CHARS[Random.nextInt(CHARS.length)] }.joinToString("")
fun generateOtp(): String = (Random.nextInt(900000) + 100000).toString()
val salt = ByteArray(16).also { java.util.Random().nextBytes(it) }
val oauthState = UUID(Random.nextLong(), Random.nextLong()).toString()
val sr = SecureRandom("fixed".toByteArray())
