package com.demo
@Composable
fun PasswordField(password: String, visible: Boolean, onChange: (String) -> Unit) {
    OutlinedTextField(
        value = password, onValueChange = onChange, label = { Text("Password") },
        visualTransformation = if (visible) VisualTransformation.None else PasswordVisualTransformation(),
    )
}
