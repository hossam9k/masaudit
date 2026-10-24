package com.demo
fun generated(accessToken: String) {
    if (BuildConfig.DEBUG) {
        Log.d(TAG, "accessToken=$accessToken")
    }
}
