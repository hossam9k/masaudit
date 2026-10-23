package com.acme.app

class Receipts : Activity() {
    fun show() {
        val receipt = intent.getParcelableExtra<Receipt>("receipt")
        startActivity(Intent(this, ReceiptActivity::class.java).putExtra("receipt", receipt))
        // startActivity(intent.getParcelableExtra("forward"))
    }
}
