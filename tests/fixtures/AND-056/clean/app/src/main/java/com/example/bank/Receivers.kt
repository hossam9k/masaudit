package com.example.bank

class Receivers(private val context: Context, private val r: BroadcastReceiver) {
    fun notExported() {
        ContextCompat.registerReceiver(context, r, IntentFilter("com.example.bank.PING"), ContextCompat.RECEIVER_NOT_EXPORTED)
    }

    fun screen() {
        ContextCompat.registerReceiver(context, r, IntentFilter(Intent.ACTION_SCREEN_OFF), ContextCompat.RECEIVER_EXPORTED)
        context.registerReceiver(r, IntentFilter(Intent.ACTION_SCREEN_OFF))
    }

    fun withPermission() {
        context.registerReceiver(r, IntentFilter("com.example.bank.PING"), "com.example.bank.permission.PING", null)
    }
}
