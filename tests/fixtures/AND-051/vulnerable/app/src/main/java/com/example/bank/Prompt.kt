package com.example.bank

fun weak() = BiometricPrompt.PromptInfo.Builder()
    .setTitle("Unlock")
    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_WEAK)
    .build()

fun weakOrPin() = BiometricPrompt.PromptInfo.Builder()
    .setAllowedAuthenticators(BIOMETRIC_WEAK or DEVICE_CREDENTIAL)
    .build()
