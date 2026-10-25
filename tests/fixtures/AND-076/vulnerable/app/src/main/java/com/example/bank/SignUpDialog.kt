package com.example.bank

import android.content.Context
import android.text.InputType
import android.widget.EditText
import android.widget.LinearLayout

class SignUpDialog(private val context: Context) {
    fun fields(layout: LinearLayout) {
        val masked = EditText(context).apply {
            hint = "Enter password"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        val cached = EditText(context).apply {
            hint = "Enter password"
            inputType = InputType.TYPE_CLASS_TEXT
        }
        val pin = EditText(context).apply {
            hint = "Enter PIN"
            inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
        }
        pin.inputType = InputType.TYPE_CLASS_NUMBER
        layout.addView(masked)
        layout.addView(cached)
        layout.addView(pin)
    }
}
