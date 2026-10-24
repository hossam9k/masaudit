package com.example.bank;

public class ReadOnlyProvider extends ContentProvider {
    @Override
    public Uri insert(Uri uri, ContentValues values) {
        throw new UnsupportedOperationException("read only");
    }
    @Override
    public int update(Uri uri, ContentValues values, String s, String[] a) {
        return 0;
    }
}
