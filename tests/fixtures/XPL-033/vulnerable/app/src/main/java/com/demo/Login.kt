package com.demo
@Composable
fun PinField(pin: String, onChange: (String) -> Unit) {
    OutlinedTextField(value = pin, onValueChange = onChange, label = { Text("PIN") })
}
