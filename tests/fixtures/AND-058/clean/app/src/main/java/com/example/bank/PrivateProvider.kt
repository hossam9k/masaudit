package com.example.bank

class PrivateProvider : ContentProvider() {
    override fun insert(uri: Uri, values: ContentValues?): Uri? {
        db.insert("notes", null, values)
        return uri
    }
    override fun delete(uri: Uri, selection: String?, args: Array<String>?): Int = 0
}
