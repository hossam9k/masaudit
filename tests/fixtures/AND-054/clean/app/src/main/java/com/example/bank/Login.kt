package com.example.bank

class Login(private val context: Context) {
    fun done(token: String) {
        val intent = Intent("com.example.bank.LOGIN_DONE").apply {
            setPackage(context.packageName)
            putExtra("auth_token", token)
        }
        context.sendBroadcast(intent)
    }

    fun explicit(token: String) {
        context.startActivity(Intent(context, HomeActivity::class.java).putExtra("session_token", token))
    }

    fun share(text: String) {
        val send = Intent(Intent.ACTION_SEND).apply { putExtra(Intent.EXTRA_TEXT, text) }
        context.startActivity(Intent.createChooser(send, null))
    }

    fun local(token: String) {
        LocalBroadcastManager.getInstance(context).sendBroadcast(Intent("LOGIN").putExtra("token", token))
    }

    fun account() {
        val add = Intent(Settings.ACTION_ADD_ACCOUNT)
        add.putExtra("authorities", arrayOf(MainApp.getAuthTokenType()))
        context.startActivity(add)
    }
}
