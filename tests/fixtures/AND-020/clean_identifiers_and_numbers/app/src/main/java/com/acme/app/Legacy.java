package com.acme.app;

class Legacy {
    static final String MISSIONS_TABLE_NAME_v2 = "missions";
    static final String T = "t";
    static final String K = "k";
    void migrate(SQLiteDatabase db, String baseQuery, long id, String column, String value) {
        db.execSQL("DROP TABLE " + MISSIONS_TABLE_NAME_v2);
        db.rawQuery(baseQuery + "where folders.id = ?", new String[] { Long.toString(id) });
        db.execSQL("UPDATE folders SET " + column + " = ? WHERE id = ?", new Object[] { value, id });
        db.execSQL(String.format("DELETE FROM %s WHERE %s NOT IN (SELECT MIN(%s) FROM %s)", T, K, K, T));
        String defaultTabs = HOME + ";" +
            NOTIFICATIONS;
        db.execSQL("ALTER TABLE accounts ADD COLUMN tabs TEXT NOT NULL DEFAULT '" + defaultTabs + "'");
    }
}
