package com.example.bank

import android.app.Activity
import android.content.Intent
import android.provider.OpenableColumns
import java.io.File
import java.io.FileOutputStream

class ImportActivity : Activity() {
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        val uri = data?.data ?: return
        var fileName = "import.bin"
        contentResolver.query(uri, null, null, null, null)?.use {
            if (it.moveToFirst()) {
                val nameIndex = it.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                fileName = it.getString(nameIndex)
            }
        }
        val outFile = File(File(filesDir, "imports"), fileName)
        contentResolver.openInputStream(uri)?.use { input ->
            FileOutputStream(outFile).use { input.copyTo(it) }
        }
        title = "Saved to ${outFile.canonicalPath}"
    }
}
