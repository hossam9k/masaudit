package com.demo
class Socket(private val keepAliveTokens: MutableSet<Long>) {
    fun add(token: Long) { Log.v(TAG, "Adding keepAliveToken: $token, current: $keepAliveTokens") }
}
