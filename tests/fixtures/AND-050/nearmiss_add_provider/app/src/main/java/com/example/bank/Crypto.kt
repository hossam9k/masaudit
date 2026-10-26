package com.example.bank

// BouncyCastle appended at the lowest priority, for algorithms the platform lacks: calls that name no
// provider still get the platform's maintained one.
fun install() {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
    Security.addProvider(BouncyCastleProvider())
}
fun cipher() = Cipher.getInstance("AES/GCM/NoPadding")
