package com.demo
import java.security.SecureRandom
fun token(): ByteArray { val b = ByteArray(16); SecureRandom().nextBytes(b); return b }
val label = "java.util.Random is not secure"
// import kotlin.random.Random
val shuffled = listOf(1, 2, 3).shuffled()
