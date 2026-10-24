package com.example.bank

fun cipher() = Cipher.getInstance("AES/GCM/NoPadding", "BC")
fun install() = Security.addProvider(BouncyCastleProvider())
fun keys() = KeyFactory.getInstance("EC", BouncyCastleProvider())
