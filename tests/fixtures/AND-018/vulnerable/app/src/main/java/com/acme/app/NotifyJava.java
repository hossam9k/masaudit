package com.acme.app;

class NotifyJava {
    PendingIntent pi(Context c, Intent i) {
        return PendingIntent.getActivity(c, 0, i, PendingIntent.FLAG_MUTABLE);
    }
}
