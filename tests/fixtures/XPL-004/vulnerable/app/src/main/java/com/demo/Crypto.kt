package com.demo
import javax.crypto.Cipher
fun a() = Cipher.getInstance("AES")
fun b() = Cipher.getInstance("AES/ECB/PKCS5Padding")
const val TRANSFORM = "AES/ECB/NoPadding"
