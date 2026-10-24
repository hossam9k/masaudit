package com.acme.app;

class DBUpgrader {
    static void upgrade(SQLiteDatabase db, int oldVersion) {
        if (oldVersion <= 15) {
            Cursor c = db.rawQuery("SELECT file_url FROM media WHERE downloaded = 1", null);
            while (c.moveToNext()) {
                String fileUrl = c.getString(0);
                // Low: a stored file path can hold a quote, but only the app wrote it.
                db.execSQL("UPDATE media SET has_picture = 1 WHERE file_url = '" + fileUrl + "'");
            }
        }
    }
}
