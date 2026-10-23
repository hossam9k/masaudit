package com.acme.app

class SafeRouter : Activity() {
    fun route() {
        val nested = IntentCompat.getParcelableExtra(intent, "next", Intent::class.java) ?: return
        val safe = IntentSanitizer.Builder()
            .allowComponent(ComponentName(this, ReceiptActivity::class.java))
            .build()
            .sanitizeByFiltering(nested)
        startActivity(safe)
    }
}
