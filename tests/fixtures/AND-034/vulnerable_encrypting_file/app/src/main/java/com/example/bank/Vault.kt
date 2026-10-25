package com.example.bank

import android.content.Context
import androidx.core.content.edit
import javax.crypto.Cipher

class Vault(private val context: Context) {
    private val demoToken = "plain-demo-value"

    private fun encrypt(plain: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        return plain.reversed() + cipher.algorithm
    }

    fun save(apiKey: String) {
        val prefs = context.getSharedPreferences("vault", Context.MODE_PRIVATE)
        prefs.edit {
            putString("session_token", demoToken)
            putString("api_key", encrypt(apiKey))
        }
    }
}
