package com.demo;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;

public class LocalStore {
    private SQLiteDatabase db;

    public LocalStore(Context context) {
        db = context.openOrCreateDatabase("ids2", Context.MODE_PRIVATE, null);
        db.execSQL("CREATE TABLE IF NOT EXISTS myuser(user VARCHAR, password VARCHAR);");
    }
}
