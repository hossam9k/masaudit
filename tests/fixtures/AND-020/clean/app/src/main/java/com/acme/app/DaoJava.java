package com.acme.app;

class DaoJava {
    static final String TABLE = "t";
    Cursor byId(SQLiteDatabase db, String id) {
        return db.rawQuery("SELECT * FROM " + TABLE + " WHERE id = ?", new String[] { id });
    }
}
