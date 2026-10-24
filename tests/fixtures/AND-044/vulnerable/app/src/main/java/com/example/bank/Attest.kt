package com.example.bank

fun attest(context: Context, nonce: ByteArray) =
    SafetyNet.getClient(context).attest(nonce, BuildConfig.SAFETYNET_KEY)
