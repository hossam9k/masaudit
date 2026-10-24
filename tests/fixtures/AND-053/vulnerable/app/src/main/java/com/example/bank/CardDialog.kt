package com.example.bank

@Composable
fun CardDialog() = Dialog(onDismissRequest = {}, properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOff)) {}
