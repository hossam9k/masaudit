package com.acme.app

fun reply(context: Context): PendingIntent =
    PendingIntent.getBroadcast(context, 0, Intent("com.example.REPLY"),
        PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
