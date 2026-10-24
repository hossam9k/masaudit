package com.demo.backup

import com.demo.archive.EncryptedBackupReader.Companion.MAC_SIZE
import javax.crypto.Cipher

fun decryptBackup(file: java.io.File, key: javax.crypto.SecretKey, iv: ByteArray): ByteArray {
    // The archive ends with a MAC that EncryptedBackupReader verifies before this runs.
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding").apply {
        init(Cipher.DECRYPT_MODE, key, javax.crypto.spec.IvParameterSpec(iv))
    }
    return cipher.doFinal(file.readBytes().copyOf((file.length() - MAC_SIZE).toInt()))
}
