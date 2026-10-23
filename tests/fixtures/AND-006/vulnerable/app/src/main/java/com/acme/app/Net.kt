package com.acme.app

val client = OkHttpClient.Builder()
    .connectionSpecs(listOf(
        ConnectionSpec.COMPATIBLE_TLS,
        ConnectionSpec.CLEARTEXT,
    ))
    .build()

val spec = ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
    .tlsVersions(TlsVersion.TLS_1_1)
    .build()
