package com.acme.wallet

import android.content.Context
import android.webkit.WebView
import androidx.biometric.BiometricPrompt

class TransferScreen(private val context: Context) {
    fun send(amount: ByteArray, prompt: BiometricPrompt, info: BiometricPrompt.PromptInfo, help: WebView) {
        WalletApi.prefs(context)
        WalletApi.encrypt(amount)
        WalletApi.confirmTransfer(prompt, info)
        WalletApi.openHelp(help)
    }
}
