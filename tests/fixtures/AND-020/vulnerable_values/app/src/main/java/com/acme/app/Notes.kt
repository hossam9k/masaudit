package com.acme.app

class Notes(private val db: SQLiteDatabase) {
    fun search(query: String) = db.rawQuery("SELECT * FROM notes WHERE title LIKE '%$query%'", null)
    fun forget(address: String) = db.execSQL("DELETE FROM identities WHERE address = '$address'")
}
