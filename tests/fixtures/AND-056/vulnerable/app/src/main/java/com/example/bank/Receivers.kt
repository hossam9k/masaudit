package com.example.bank

const val ACTION_CUSTOM = "com.example.bank.CUSTOM"

class Receivers(private val context: Context, private val r: BroadcastReceiver) {
    fun exported() {
        ContextCompat.registerReceiver(context, r, IntentFilter("com.example.bank.PING"), ContextCompat.RECEIVER_EXPORTED)
    }

    fun implicit() {
        context.registerReceiver(r, IntentFilter(ACTION_CUSTOM))
    }
}
