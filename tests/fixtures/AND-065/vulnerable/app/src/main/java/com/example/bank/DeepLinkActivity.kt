package com.example.bank

class DeepLinkActivity : Activity() {
    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        val payload = intent.getSerializableExtra("payload") as? Transfer
    }
}
