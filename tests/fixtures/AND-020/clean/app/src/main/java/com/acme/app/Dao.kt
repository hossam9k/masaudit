package com.acme.app

private const val TABLE_NAME = "orders"

class Dao(private val db: SQLiteDatabase) {
    fun find(orderId: String) = db.rawQuery("SELECT * FROM orders WHERE id = ?", arrayOf(orderId))
    fun clear() = db.execSQL("DELETE FROM $TABLE_NAME")
    fun byId(args: Array<String>) = db.rawQuery("SELECT * FROM ${Contract.TABLE} WHERE id = ?", args)
    // db.rawQuery("SELECT * FROM orders WHERE id = " + orderId, null)
}
