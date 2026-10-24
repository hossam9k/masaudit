package com.example.bank

import android.os.Environment

fun exportStatement(pdf: ByteArray) {
    val dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
    FileOutputStream(File(dir, "statement.pdf")).use { it.write(pdf) }
}
