package com.example.bank

// The URI is this app's own FileProvider output, not one another app sent.
fun move(context: Context, contentUri: Uri): File {
    val filename = contentUri.lastPathSegment ?: "photo.jpg"
    return File(context.cacheDir, filename)
}
