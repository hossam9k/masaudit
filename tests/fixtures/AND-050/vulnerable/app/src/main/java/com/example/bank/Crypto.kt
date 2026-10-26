package com.example.bank

fun cipher() = Cipher.getInstance("AES/GCM/NoPadding", "BC")
fun install() = Security.insertProviderAt(BouncyCastleProvider(), 1)
fun keys() = KeyFactory.getInstance("EC", BouncyCastleProvider())
