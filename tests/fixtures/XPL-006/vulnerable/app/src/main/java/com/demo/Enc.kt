package com.demo
private val IV = "1234567890abcdef".toByteArray()
fun a(key: SecretKey) = Cipher.getInstance("AES/CBC/PKCS5Padding").init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(ByteArray(16)))
fun b(key: SecretKey) = Cipher.getInstance("AES/GCM/NoPadding").init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)))
fun c(key: SecretKey) = Cipher.getInstance("AES/CBC/PKCS5Padding").init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(IV))
