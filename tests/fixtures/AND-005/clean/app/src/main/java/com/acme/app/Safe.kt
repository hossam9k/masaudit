package com.acme.app

import org.apache.http.conn.ssl.NoopHostnameVerifier

class PinningTrustManager(private val defaultTm: X509TrustManager) : X509TrustManager {
    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        defaultTm.checkClientTrusted(chain, authType)
    }
    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        defaultTm.checkServerTrusted(chain, authType)
    }
    override fun getAcceptedIssuers(): Array<X509Certificate> = defaultTm.acceptedIssuers
}

// .hostnameVerifier { _, _ -> true } disables host checks: never do this
val note = "ALLOW_ALL_HOSTNAME_VERIFIER is unsafe"
val client = OkHttpClient.Builder()
    .hostnameVerifier { _, session -> HttpsURLConnection.getDefaultHostnameVerifier().verify("api.example.com", session) }
    .build()
