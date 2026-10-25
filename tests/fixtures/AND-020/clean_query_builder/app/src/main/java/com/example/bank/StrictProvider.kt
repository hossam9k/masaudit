package com.example.bank

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.sqlite.SQLiteQueryBuilder
import android.net.Uri

class StrictProvider : ContentProvider() {
    private lateinit var helper: StudentDbHelper

    override fun onCreate(): Boolean {
        helper = StudentDbHelper(context!!)
        return true
    }

    override fun query(
        uri: Uri,
        projection: Array<String>?,
        selection: String?,
        selectionArgs: Array<String>?,
        sortOrder: String?
    ): Cursor? {
        val qb = SQLiteQueryBuilder()
        qb.tables = "students"
        qb.setStrict(true)
        qb.appendWhereEscapeString(uri.lastPathSegment ?: "")
        qb.appendWhere("deleted = 0")
        return qb.query(helper.readableDatabase, projection, selection, selectionArgs, null, null, sortOrder)
    }

    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = 0
}
