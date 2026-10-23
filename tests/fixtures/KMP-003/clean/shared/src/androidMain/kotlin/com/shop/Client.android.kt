package com.shop
import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp
import okhttp3.CertificatePinner

actual fun createPinnedHttpClient(): HttpClient = HttpClient(OkHttp) {
    engine {
        config {
            certificatePinner(
                CertificatePinner.Builder()
                    .add(CertificatePins.HOST, CertificatePins.CURRENT, CertificatePins.BACKUP)
                    .build()
            )
        }
    }
}
