package com.example.bank

import android.content.Context
import android.widget.Button
import android.widget.LinearLayout

class PaymentScreen(private val context: Context) {
    fun build(layout: LinearLayout) {
        val payButton = Button(context).apply {
            text = "Confirm payment"
        }
        layout.addView(payButton)
        val protectedButton = Button(context).apply {
            text = "Transfer money"
            filterTouchesWhenObscured = true
        }
        layout.addView(protectedButton)
        val helpButton = Button(context).apply {
            text = "Help"
        }
        layout.addView(helpButton)
    }
}
