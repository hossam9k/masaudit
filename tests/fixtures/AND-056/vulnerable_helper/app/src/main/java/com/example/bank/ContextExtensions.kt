package com.example.bank

// A helper that registers whatever filter it's given as exported: the finding belongs at its callers.
fun Context.registerExportedReceiver(
    receiver: BroadcastReceiver,
    intentFilter: IntentFilter,
) {
    ContextCompat.registerReceiver(this, receiver, intentFilter, ContextCompat.RECEIVER_EXPORTED)
}
