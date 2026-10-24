package com.demo
val info = BiometricPrompt.PromptInfo.Builder()
    .setTitle("Confirm transfer")
    .setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
    .build()
val legacy = BiometricPrompt.PromptInfo.Builder().setDeviceCredentialAllowed(true).build()
