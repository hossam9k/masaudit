package com.demo
fun save(token: String) {
    Log.d(TAG, "token refreshed")
    Log.w(TAG, "Wrong password entered")
    Log.e(TAG, "Failed to save", error)
    // Log.d(TAG, "saved token=$token")
    Log.d(KEY_TOKEN, "stored")
}
