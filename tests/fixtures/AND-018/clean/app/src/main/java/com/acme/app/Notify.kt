package com.acme.app

fun open(context: Context): PendingIntent {
    val intent = Intent(context, ResultReceiverActivity::class.java)
    // PendingIntent.FLAG_MUTABLE would let the receiver change the intent
    Log.d("notify", "not using FLAG_MUTABLE")
    return PendingIntent.getActivity(context, 0, intent,
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
}
