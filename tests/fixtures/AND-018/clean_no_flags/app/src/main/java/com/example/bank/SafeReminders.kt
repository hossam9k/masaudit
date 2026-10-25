package com.example.bank

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.PendingIntentCompat

class SafeReminders(private val context: Context, private val flags: Int) {
    fun build(): List<PendingIntent?> {
        val explicit = Intent(context, MainActivity::class.java)
        val a = PendingIntent.getActivity(context, 0, explicit, 0)
        val view = Intent(Intent.ACTION_VIEW)
        val b = PendingIntent.getActivity(context, 1, view, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val c = PendingIntentCompat.getActivity(context, 2, view, 0, false)
        val d = PendingIntent.getActivity(context, 3, view, flags)
        return listOf(a, b, c, d)
    }
}
