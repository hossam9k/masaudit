package com.example.bank;

class ShareReceiver extends Activity {
    void handle() {
        Uri uri = getIntent().getParcelableExtra(Intent.EXTRA_STREAM);
        String fileName = uri.getLastPathSegment();
        File out = new File(getFilesDir(), fileName);
    }
}
