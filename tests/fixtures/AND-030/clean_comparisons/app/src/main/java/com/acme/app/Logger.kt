package com.acme.app

class FormattedLogger(private val level: HttpLoggingInterceptor.Level) {
    fun log(message: String) {
        if (level != HttpLoggingInterceptor.Level.BODY) return
    }
}

fun levelFor(name: String) = when (name) {
    "BODY" -> HttpLoggingInterceptor.Level.BODY
    else -> HttpLoggingInterceptor.Level.NONE
}

fun configure(logHttpBody: Boolean) = HttpLoggingInterceptor().apply {
    setLevel(
        level = HttpLoggingInterceptor.Level.BODY
            .takeIf { logHttpBody }
            ?: HttpLoggingInterceptor.Level.BASIC,
    )
}

val custom = FormattedLogger(HttpLoggingInterceptor.Level.BODY)
