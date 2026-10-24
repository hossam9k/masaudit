package com.demo
val info = BiometricPrompt.PromptInfo.Builder()
    .setTitle("Confirm transfer")
    .setAllowedAuthenticators(BIOMETRIC_STRONG)
    .setNegativeButtonText("Cancel")
    .build()
