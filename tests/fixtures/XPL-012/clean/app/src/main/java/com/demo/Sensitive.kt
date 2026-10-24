package com.demo
fun copyPassword(clipboard: ClipboardManager, password: String) {
    val clip = ClipData.newPlainText("password", password)
    clip.description.extras = PersistableBundle().apply {
        putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
    }
    clipboard.setPrimaryClip(clip)
}
