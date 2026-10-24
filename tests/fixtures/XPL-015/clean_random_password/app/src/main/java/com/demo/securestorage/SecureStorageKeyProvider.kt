package com.demo.securestorage

class SecureStorageKeyProvider(
    private val random: RandomBytesGenerator,
    private val generator: SecureStorageKeyGenerator,
) {
    fun l2Key(salt: ByteArray) = run {
        val newPassword = random.generateBytes(PASSWORD_SIZE)
        generator.generateKeyFromPassword(newPassword.toBase64(), salt)
    }

    companion object {
        private const val PASSWORD_SIZE = 32
    }
}
