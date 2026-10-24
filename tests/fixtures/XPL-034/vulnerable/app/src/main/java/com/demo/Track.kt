package com.demo
fun identify(user: User) {
    FirebaseAnalytics.getInstance(ctx).setUserId(user.email)
    FirebaseCrashlytics.getInstance().setCustomKey("phone", user.phoneNumber)
}
