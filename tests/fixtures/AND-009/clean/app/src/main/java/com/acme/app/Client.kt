package com.acme.app

fun client(pinner: CertificatePinner, logging: Interceptor): OkHttpClient {
    val builder = OkHttpClient.Builder().certificatePinner(pinner)
    // if (BuildConfig.DEBUG) builder.certificatePinner(p) would be wrong
    if (BuildConfig.DEBUG) {
        builder.addInterceptor(logging)
    }
    return builder.build()
}
