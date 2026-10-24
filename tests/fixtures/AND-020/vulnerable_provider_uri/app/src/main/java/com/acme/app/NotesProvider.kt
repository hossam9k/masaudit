package com.acme.app

// Must stay high: the query is built from a content URI another app sends.
class NotesProvider : ContentProvider() {
    override fun query(uri: Uri, p: Array<String>?, s: String?, a: Array<String>?, o: String?): Cursor? {
        val id = uri.lastPathSegment
        return db.rawQuery("SELECT * FROM notes WHERE id = '$id'", null)
    }
}
