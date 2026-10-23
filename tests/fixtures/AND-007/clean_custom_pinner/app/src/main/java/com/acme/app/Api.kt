package com.acme.app

import okhttp3.OkHttpClient

val client = OkHttpClient.Builder()
    .addInterceptor(SslPinningInterceptor(BuildPins.ALL))
    .build()
