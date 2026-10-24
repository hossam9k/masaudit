package com.demo
fun notifyOtp(ctx: Context, otpCode: String) {
    val n = NotificationCompat.Builder(ctx, "otp")
        .setContentTitle("Your sign-in code")
        .setContentText("Code: $otpCode")
        .build()
}
fun notifyBalance(ctx: Context, balance: String) {
    NotificationCompat.Builder(ctx, "acct").setContentText(balance).build()
}
