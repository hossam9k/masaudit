package com.example.bank

class Login(private val context: Context) {
    fun done(token: String) {
        val intent = Intent("com.example.bank.LOGIN_DONE").apply {
            putExtra("auth_token", token)
        }
        context.sendBroadcast(intent)
    }
}
