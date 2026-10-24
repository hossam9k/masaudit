package com.example.bank

fun cipher() = Cipher.getInstance("AES/GCM/NoPadding")
fun keystore() = KeyStore.getInstance("AndroidKeyStore")
fun generator() = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
fun conscrypt() = Security.insertProviderAt(Conscrypt.newProvider(), 1)
// Cipher.getInstance("AES", "BC")
