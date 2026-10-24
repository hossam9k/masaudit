package com.example.bank

fun payPrompt() = BiometricPrompt.PromptInfo.Builder()
    .setTitle("Approve transfer")
    .setConfirmationRequired(false)
    .setAllowedAuthenticators(BIOMETRIC_STRONG)
    .build()
