package com.acme.app;

class Feeds {
    void fix(SQLiteDatabase db, String fileUrl) {
        db.execSQL("UPDATE media SET has_pic=1 WHERE file_url='" + fileUrl + "'");
    }
    Cursor byName(SQLiteDatabase db) {
        return db.rawQuery("SELECT * FROM users WHERE name = '" + getIntent().getStringExtra("n") + "'", null);
    }
}
