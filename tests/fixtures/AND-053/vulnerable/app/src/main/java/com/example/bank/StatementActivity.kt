package com.example.bank

class StatementActivity : BaseSecureActivity() {
    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }
}
