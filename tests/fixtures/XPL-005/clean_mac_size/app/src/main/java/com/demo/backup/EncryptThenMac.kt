package com.demo.backup

import javax.crypto.Cipher
import javax.crypto.Mac

fun seal(macKey: javax.crypto.SecretKey, data: ByteArray): ByteArray {
    val mac = Mac.getInstance("HmacSHA256").apply { init(macKey) }
    val c = Cipher.getInstance("AES/CBC/PKCS5Padding")
    return c.doFinal(data) + mac.doFinal(data)
}
