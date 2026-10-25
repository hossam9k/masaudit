package com.example.bank

import android.app.PendingIntent
import android.content.Context
import android.content.Intent

class Reminders(private val context: Context) {
    fun build(): List<PendingIntent> {
        val view = Intent(Intent.ACTION_VIEW)
        val open = PendingIntent.getActivity(context, 0, view, PendingIntent.FLAG_UPDATE_CURRENT)
        val custom = Intent("com.example.bank.CUSTOM_ACTION")
        val ping = PendingIntent.getBroadcast(context, 2, custom, 0)
        return listOf(open, ping)
    }
}
