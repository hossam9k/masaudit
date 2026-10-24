package com.example.bank

fun enc() = KeyGenParameterSpec.Builder("enc", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT).build()
fun sig() = KeyGenParameterSpec.Builder("sig", KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY).build()
fun signNumeric() = KeyGenParameterSpec.Builder("sig2", 12).build()
fun wrap() = KeyGenParameterSpec.Builder("wrap", KeyProperties.PURPOSE_WRAP_KEY).build()
