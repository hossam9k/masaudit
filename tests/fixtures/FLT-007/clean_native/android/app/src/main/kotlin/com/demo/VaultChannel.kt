package com.demo

import androidx.biometric.BiometricPrompt

fun unlock(prompt: BiometricPrompt, info: BiometricPrompt.PromptInfo, cipher: javax.crypto.Cipher) {
    prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
}
