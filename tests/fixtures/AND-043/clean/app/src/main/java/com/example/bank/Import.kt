package com.example.bank

class Import(private val context: Context) {
    fun save(uri: Uri): File {
        val cursor = context.contentResolver.query(uri, null, null, null, null)!!
        val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
        cursor.moveToFirst()
        val name = cursor.getString(nameIndex)
        val target = File(context.filesDir, File(name).name)
        return target
    }

    fun saveChecked(uri: Uri, name: String): File {
        val display = queryName(uri, OpenableColumns.DISPLAY_NAME)
        val file = File(context.filesDir, display)
        require(file.canonicalPath.startsWith(context.filesDir.canonicalPath + File.separator))
        return file
    }

    fun saveGenerated(uri: Uri): File {
        val shown = queryName(uri, OpenableColumns.DISPLAY_NAME)
        title = shown
        return File(context.filesDir, UUID.randomUUID().toString())
    }
}
