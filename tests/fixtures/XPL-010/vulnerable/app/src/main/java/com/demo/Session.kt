package com.demo
fun save(token: String, password: String) {
    Log.d(TAG, "saved token=$token")
    Log.i(TAG, "pw: " + password)
    println("auth ${session.accessToken}")
}
