package com.demo
fun derive(password: CharArray, salt: ByteArray) = PBEKeySpec(password, salt, 600_000, 256)
fun sha512(password: CharArray, salt: ByteArray): SecretKey {
    val f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512")
    return f.generateSecret(PBEKeySpec(password, salt, 210_000, 256))
}
fun configured(password: CharArray, salt: ByteArray, rounds: Int) = PBEKeySpec(password, salt, rounds, 256)
