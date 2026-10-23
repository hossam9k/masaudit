package com.acme.app;

class DaoJava {
    Cursor byName(SQLiteDatabase db, String name) {
        return db.rawQuery(String.format("SELECT * FROM t WHERE name = '%s'", name), null);
    }
}
