package com.example.bank

import android.content.Context
import java.io.File

class SecretWriter(private val context: Context) {
    fun write(value: String) {
        val dir = context.filesDir
        File(dir, "secret.txt").writeText(value)
        File(context.filesDir, "cache_index.json").writeText("{}")
        context.openFileOutput("excluded_token.txt", Context.MODE_PRIVATE).use { it.write(value.toByteArray()) }
    }
}
