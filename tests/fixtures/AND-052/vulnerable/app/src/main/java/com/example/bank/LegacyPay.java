package com.example.bank;

class LegacyPay {
    BiometricPrompt.PromptInfo info() {
        return new BiometricPrompt.PromptInfo.Builder().setConfirmationRequired(false).build();
    }
}
