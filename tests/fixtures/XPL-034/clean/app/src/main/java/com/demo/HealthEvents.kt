package com.demo

import android.content.Context
import android.os.Bundle
import com.google.firebase.analytics.FirebaseAnalytics
import com.google.firebase.analytics.logEvent

class HealthEvents(context: Context) {
    private val analytics = FirebaseAnalytics.getInstance(context)

    fun recordScreen(screen: String) {
        analytics.logEvent("screen_view") {
            param("screen_name", screen)
        }
    }

    fun recordServerHealth(latencyMs: Long) {
        val bundle = Bundle()
        bundle.putLong("server_health_latency", latencyMs)
        analytics.logEvent("server_health", bundle)
    }

    fun recordEmailScreenOpened() {
        analytics.logEvent("email_screen_opened", null)
    }
}
