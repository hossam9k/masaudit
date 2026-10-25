package com.demo

import android.content.Context
import android.os.Bundle
import com.google.firebase.analytics.FirebaseAnalytics
import com.google.firebase.analytics.logEvent

class HealthEvents(context: Context) {
    private val analytics = FirebaseAnalytics.getInstance(context)

    fun recordBloodType(userId: String, bloodType: String) {
        analytics.logEvent("user_blood_type") {
            param("user_id", userId)
            param("blood_type", bloodType)
        }
    }

    fun recordSignup(mail: String) {
        val bundle = Bundle()
        bundle.putString("email", mail)
        analytics.logEvent("sign_up", bundle)
    }
}
