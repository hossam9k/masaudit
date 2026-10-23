package com.demo
import kotlin.random.Random
fun token() = Random.nextBytes(16)
fun seeded() = SecureRandom().apply { setSeed(System.currentTimeMillis()) }
