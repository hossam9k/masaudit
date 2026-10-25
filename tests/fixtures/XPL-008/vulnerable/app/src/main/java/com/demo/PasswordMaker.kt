package com.demo

import java.util.Random

class PasswordMaker {
    fun make(): String {
        val length = 16
        val characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        val random = Random()
        val password = StringBuilder(length)
        for (i in 0 until length) {
            password.append(characters[random.nextInt(characters.length)])
        }
        return password.toString()
    }
}
