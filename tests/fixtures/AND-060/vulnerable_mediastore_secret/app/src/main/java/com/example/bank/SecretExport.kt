package com.example.bank

import android.content.ContentValues
import android.content.Context
import android.os.Environment
import android.provider.MediaStore

class SecretExport(private val context: Context) {
    fun save(bytes: ByteArray) {
        val values = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, "secretFile.txt")
            put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
        }
        val uri = context.contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values) ?: return
        context.contentResolver.openOutputStream(uri)?.use { it.write(bytes) }
    }
}
