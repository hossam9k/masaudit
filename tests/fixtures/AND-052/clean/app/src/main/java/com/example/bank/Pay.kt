package com.example.bank

fun payPrompt() = BiometricPrompt.PromptInfo.Builder()
    .setTitle("Approve transfer")
    .setConfirmationRequired(true)
    .build()
