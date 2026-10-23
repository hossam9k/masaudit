package com.demo
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
fun a() = Cipher.getInstance("AES/GCM/NoPadding")
fun k(bytes: ByteArray) = SecretKeySpec(bytes, "AES")
fun r() = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
// Cipher.getInstance("AES/ECB/PKCS5Padding") was removed in 2.0
