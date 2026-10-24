package com.demo
fun copyLink(clipboard: ClipboardManager, shareUrl: String) {
    clipboard.setPrimaryClip(ClipData.newPlainText("link", shareUrl))
}
