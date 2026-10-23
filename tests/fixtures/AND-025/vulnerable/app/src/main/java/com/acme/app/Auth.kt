package com.acme.app

import androidx.biometric.BiometricPrompt

fun confirm(activity: FragmentActivity, promptInfo: BiometricPrompt.PromptInfo, callback: BiometricPrompt.AuthenticationCallback) {
    val biometricPrompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback)
    biometricPrompt.authenticate(promptInfo)
}
