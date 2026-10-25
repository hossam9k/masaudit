package com.example.bank

import android.app.PendingIntent
import android.content.Context
import android.content.Intent

class Reminders(private val context: Context) {
    fun build(): PendingIntent {
        val custom = Intent("com.example.bank.CUSTOM_ACTION")
        return PendingIntent.getBroadcast(context, 2, custom, 0)
    }
}
