package com.demo
fun identify(user: User) {
    FirebaseAnalytics.getInstance(ctx).setUserId(user.pseudonymousId)
    FirebaseCrashlytics.getInstance().setCustomKey("plan", user.plan)
}
