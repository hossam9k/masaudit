package com.example.bank

class Import(private val context: Context) {
    fun save(uri: Uri): File {
        val cursor = context.contentResolver.query(uri, null, null, null, null)!!
        val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
        cursor.moveToFirst()
        val name = cursor.getString(nameIndex)
        val target = File(context.filesDir, name)
        context.contentResolver.openInputStream(uri)!!.use { it.copyTo(target.outputStream()) }
        return target
    }
}
