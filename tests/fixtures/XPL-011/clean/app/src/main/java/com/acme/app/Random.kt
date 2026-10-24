package com.acme.app
class Holder(random: SecureRandom) {
    private val key = ByteArray(32).also { random.nextBytes(it) }
    fun spec() = SecretKeySpec(key, "AES")
}
