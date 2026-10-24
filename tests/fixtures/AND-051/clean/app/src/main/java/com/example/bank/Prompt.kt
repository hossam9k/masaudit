package com.example.bank

fun strong() = BiometricPrompt.PromptInfo.Builder()
    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
    .build()

fun support(manager: BiometricManager) = when {
    manager.canAuthenticate(BIOMETRIC_STRONG) == BIOMETRIC_SUCCESS -> "class3"
    manager.canAuthenticate(BIOMETRIC_WEAK) == BIOMETRIC_SUCCESS -> "class2"
    else -> "none"
}
