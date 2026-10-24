package com.example.bank

import android.content.ContentValues
import android.provider.MediaStore

// Low: a download the user asked for, into Downloads.
fun saveDownload(resolver: ContentResolver, name: String, bytes: ByteArray) {
    val cv = ContentValues().apply { put(MediaStore.MediaColumns.DISPLAY_NAME, name) }
    val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv)
    resolver.openOutputStream(uri!!)?.use { it.write(bytes) }
}
