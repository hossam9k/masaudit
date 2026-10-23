package com.acme.app

val trustAll = object : X509TrustManager {
    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
}

val client = OkHttpClient.Builder()
    .sslSocketFactory(factory, trustAll)
    .hostnameVerifier { _, _ -> true }
    .build()
