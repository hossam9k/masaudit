package com.example.bank

fun expire(context: Context) {
    context.sendBroadcast(Intent("com.example.bank.SESSION_EXPIRED").setPackage(context.packageName))
    context.startService(Intent(context, SyncService::class.java))
    context.startActivity(Intent("com.google.zxing.client.android.SCAN"))
    LocalBroadcastManager.getInstance(context).sendBroadcast(Intent("com.example.bank.LOCAL"))
    context.sendBroadcast(Intent("com.example.bank.PRIVATE"), "com.example.bank.permission.INTERNAL")
}
