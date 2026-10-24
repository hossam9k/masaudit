package com.demo
private const val ITERATIONS = 10_000
fun derive(password: CharArray, salt: ByteArray): SecretKey {
    val f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
    return f.generateSecret(PBEKeySpec(password, salt, ITERATIONS, 256))
}
fun legacy(password: CharArray, salt: ByteArray) = PBEKeySpec(password, salt, 1000, 256)
