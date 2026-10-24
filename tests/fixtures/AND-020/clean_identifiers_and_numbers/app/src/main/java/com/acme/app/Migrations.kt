package com.acme.app

const val TABLE_NAME = "log"
const val ID = "_id"

class Migrations(private val db: SQLiteDatabase) {
    fun drop(table: Table) = db.execSQL("DROP TABLE IF EXISTS ${table.name}")
    fun dropTrigger(trigger: String) = db.execSQL("DROP TRIGGER IF EXISTS $trigger")
    fun add(tableName: String, columnName: String) = db.execSQL("ALTER TABLE $tableName ADD COLUMN `$columnName` TEXT")
    fun info(tableName: String) = db.rawQuery("PRAGMA table_info($tableName)", null)
    fun analyze(table: String) = db.execSQL("ANALYZE $table")
    fun index() = db.execSQL("CREATE INDEX i ON mms (_id, type) WHERE type & ${0x300000000L} != 0")
    fun move(index: Int, id: Long) = db.execSQL("UPDATE sticker_pack SET position = $index WHERE _id = $id")
    fun trim(logCount: Int) = db.execSQL("DELETE FROM $TABLE_NAME WHERE $ID < (SELECT MAX($ID) FROM $TABLE_NAME LIMIT ${logCount / 2})")
    fun returning(query: Query) = db.rawQuery("${query.where} RETURNING ${MessageTable.ID}", query.whereArgs)
    fun batch() { val batchTable = "batch_delete"; db.execSQL("DELETE FROM $batchTable") }
    fun skip() = db.execSQL("ALTER TABLE feeds ADD COLUMN skip INTEGER DEFAULT " + SkipSilence.GLOBAL.code)
    fun count(selectionSet: String, selectionArguments: Array<String>) =
        db.rawQuery("SELECT COUNT(id) FROM folders WHERE id $selectionSet", selectionArguments)
    fun flags(newState: Boolean) = db.execSQL("UPDATE messages SET flagged = " + (if (newState) "1" else "0"))
    fun key() = db.execSQL("UPDATE folder SET key = '${Base64.encodeWithPadding(generateKey())}'")
    fun dependents(tableName: String) = db.rawQuery("SELECT name FROM sqlite_schema WHERE tbl_name='$tableName'", null)
    fun messages() = dependents("message")
}
