// Android enforces the shared pins with OkHttp's CertificatePinner.
package com.bank.net

import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp
import okhttp3.CertificatePinner

actual fun apiClient(): HttpClient = HttpClient(OkHttp) {
    engine {
        config {
            certificatePinner(CertificatePinner.Builder().add("api.bank.example", *apiPins.toTypedArray()).build())
        }
    }
}
