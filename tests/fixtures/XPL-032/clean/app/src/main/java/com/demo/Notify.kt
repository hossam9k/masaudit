package com.demo
fun notifyOtp(ctx: Context, otpCode: String) {
    val public = NotificationCompat.Builder(ctx, "otp").setContentText("New sign-in code").build()
    NotificationCompat.Builder(ctx, "otp")
        .setContentText("Code: $otpCode")
        .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
        .setPublicVersion(public)
        .build()
}
fun notifyDownload(ctx: Context, fileName: String) {
    NotificationCompat.Builder(ctx, "dl").setContentText("Downloaded $fileName").build()
}
