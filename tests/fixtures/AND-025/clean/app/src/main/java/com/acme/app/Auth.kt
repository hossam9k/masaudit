package com.acme.app

import androidx.biometric.BiometricPrompt

fun confirm(activity: FragmentActivity, promptInfo: BiometricPrompt.PromptInfo, signature: Signature, callback: BiometricPrompt.AuthenticationCallback) {
    // biometricPrompt.authenticate(promptInfo) alone would be decorative
    BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback)
        .authenticate(promptInfo, BiometricPrompt.CryptoObject(signature))
}
