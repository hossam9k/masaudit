package com.demo
fun hashPassword(p: String) = MessageDigest.getInstance("SHA-1").digest(p.toByteArray())
fun verifySignature(payload: ByteArray, expected: ByteArray): Boolean {
    val digest = MessageDigest.getInstance("MD5")
    return digest.digest(payload).contentEquals(expected)
}
