package com.acme.app

fun client(pinner: CertificatePinner): OkHttpClient {
    val builder = OkHttpClient.Builder()
    if (!BuildConfig.DEBUG) {
        builder.certificatePinner(pinner)
    }
    return builder.build()
}

fun other(builder: OkHttpClient.Builder, p: CertificatePinner) =
    if (BuildConfig.PINNING_ENABLED) builder.certificatePinner(p).build() else builder.build()
