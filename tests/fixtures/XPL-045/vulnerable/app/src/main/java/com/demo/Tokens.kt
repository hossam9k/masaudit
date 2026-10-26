package com.demo

import java.util.Calendar
import java.util.Date

class Tokens {
    fun make(): String {
        val random1 = Date().time.toInt()
        val c = Calendar.getInstance()
        val random2 = c.get(Calendar.MILLISECOND)
        val sessionToken = System.currentTimeMillis().toString()
        return "$random1$random2$sessionToken"
    }
}

fun hashed(): String {
    val resetToken = md5(System.currentTimeMillis().toString())
    return resetToken
}
