package com.example.bank

import android.app.Activity
import android.content.Intent
import android.provider.OpenableColumns
import java.io.File
import java.io.FileOutputStream

class SafeImportActivity : Activity() {
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        val uri = data?.data ?: return
        var fileName = "import.bin"
        contentResolver.query(uri, null, null, null, null)?.use {
            if (it.moveToFirst()) {
                fileName = it.getString(it.getColumnIndex(OpenableColumns.DISPLAY_NAME))
            }
        }
        val dir = File(filesDir, "imports")
        val outFile = File(dir, fileName)
        require(outFile.canonicalPath.startsWith(dir.canonicalPath + File.separator))
        contentResolver.openInputStream(uri)?.use { input ->
            FileOutputStream(outFile).use { input.copyTo(it) }
        }
    }
}
