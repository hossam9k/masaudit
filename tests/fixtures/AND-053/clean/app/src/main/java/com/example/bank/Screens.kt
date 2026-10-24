package com.example.bank

fun Window.applyScreenSecurity(enabled: Boolean) {
    if (enabled) addFlags(WindowManager.LayoutParams.FLAG_SECURE) else clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
}

@Composable
fun SecureWindowEffect(activity: Activity) {
    DisposableEffect(activity) {
        activity.setRecentsScreenshotEnabled(false)
        onDispose { activity.setRecentsScreenshotEnabled(true) }
    }
}
