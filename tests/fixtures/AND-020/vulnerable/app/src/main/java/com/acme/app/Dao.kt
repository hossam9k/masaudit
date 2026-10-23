package com.acme.app

class Dao(private val db: SQLiteDatabase) {
    fun find(orderId: String) = db.rawQuery("SELECT * FROM orders WHERE id = " + orderId, null)
    fun delete(user: String) = db.execSQL("DELETE FROM orders WHERE user = '$user'")
}
