package com.example.bank

fun expire(context: Context) {
    context.sendBroadcast(Intent("com.example.bank.SESSION_EXPIRED"))
}
