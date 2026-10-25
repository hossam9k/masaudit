package com.demo;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;

public class LocalStore {
    private SQLiteDatabase db;

    public LocalStore(Context context) {
        db = context.openOrCreateDatabase("notes", Context.MODE_PRIVATE, null);
        // A share link token, not a credential.
        db.execSQL("CREATE TABLE IF NOT EXISTS shares(id INTEGER, token VARCHAR, title VARCHAR);");
        db.execSQL("CREATE TABLE IF NOT EXISTS notes(id INTEGER, body TEXT, password_hint TEXT);");
    }
}
