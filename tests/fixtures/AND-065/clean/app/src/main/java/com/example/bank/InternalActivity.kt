package com.example.bank

class InternalActivity : Activity() {
    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        val payload = intent.getSerializableExtra("payload") as? Transfer
    }
}
