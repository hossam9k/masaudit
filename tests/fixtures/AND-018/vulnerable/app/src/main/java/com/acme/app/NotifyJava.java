package com.acme.app;

class NotifyJava {
    PendingIntent pi(Context c, Uri uri) {
        Intent i = new Intent(Intent.ACTION_VIEW, uri);
        return PendingIntent.getActivity(c, 0, i, PendingIntent.FLAG_MUTABLE);
    }
}
