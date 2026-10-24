package com.example.bank

fun mixed() = KeyGenParameterSpec.Builder("k1", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_SIGN).build()
fun numeric() = KeyGenParameterSpec.Builder("k2", 7).build()
