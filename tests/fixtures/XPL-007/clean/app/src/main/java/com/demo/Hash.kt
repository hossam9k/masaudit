package com.demo
val sha = MessageDigest.getInstance("SHA-256")
val label = "MD5 is broken"
// MessageDigest.getInstance("MD5")
val mac = Mac.getInstance("HmacSHA256")
fun cacheKey(url: String): String = hex(MessageDigest.getInstance("MD5").digest(url.toByteArray()))
fun performBackup(out: OutputStream) { val digest = MessageDigest.getInstance("MD5") }
fun computeCramMd5(username: String, password: String): ByteArray {
    val md = MessageDigest.getInstance("MD5")
    return md.digest(password.toByteArray())
}
