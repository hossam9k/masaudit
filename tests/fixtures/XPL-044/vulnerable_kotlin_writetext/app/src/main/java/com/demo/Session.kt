package com.demo

import android.content.Context
import java.io.File

class Session(private val context: Context) {
    fun save(token: String) {
        File(context.filesDir, "session.txt").writeText(token)
    }
}
