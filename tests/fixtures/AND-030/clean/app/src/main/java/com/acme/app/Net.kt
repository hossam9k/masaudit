package com.acme.app

val logging = HttpLoggingInterceptor().apply {
    level = if (BuildConfig.DEBUG) HttpLoggingInterceptor.Level.BODY
            else HttpLoggingInterceptor.Level.NONE
}

fun builder(b: OkHttpClient.Builder) {
    if (BuildConfig.DEBUG) {
        b.addInterceptor(HttpLoggingInterceptor().apply { level = HttpLoggingInterceptor.Level.BODY })
    }
    b.addInterceptor(HttpLoggingInterceptor().apply { level = HttpLoggingInterceptor.Level.BASIC })
    // level = HttpLoggingInterceptor.Level.BODY
}
