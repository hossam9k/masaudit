package com.demo

// Constants name the events; the bundle holds a count, not the user's email.
fun opened(analytics: FirebaseAnalytics) {
    val params = Bundle()
    params.putInt("count", 1)
    analytics.logEvent(Events.EMAIL_SETTINGS_OPENED, params)
}
