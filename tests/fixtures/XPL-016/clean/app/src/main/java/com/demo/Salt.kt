package com.demo
fun derive(password: CharArray): Pair<ByteArray, PBEKeySpec> {
    val salt = ByteArray(16)
    SecureRandom().nextBytes(salt)
    return salt to PBEKeySpec(password, salt, 600_000, 256)
}
fun restore(password: CharArray, storedSalt: ByteArray) = PBEKeySpec(password, storedSalt, 600_000, 256)
