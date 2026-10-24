package com.demo
fun copyPassword(clipboard: ClipboardManager, password: String) {
    clipboard.setPrimaryClip(ClipData.newPlainText("password", password))
}
fun copyOtp(clipboard: ClipboardManager, otpCode: String) {
    val clip = ClipData.newPlainText("code", otpCode)
    clipboard.setPrimaryClip(clip)
}
