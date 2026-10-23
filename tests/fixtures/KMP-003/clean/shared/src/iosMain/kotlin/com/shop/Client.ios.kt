package com.shop
import io.ktor.client.HttpClient
import io.ktor.client.engine.darwin.Darwin
import io.ktor.client.engine.darwin.certificates.CertificatePinner

actual fun createPinnedHttpClient(): HttpClient = HttpClient(Darwin) {
    engine {
        handleChallenge(
            CertificatePinner.Builder()
                .add(CertificatePins.HOST, CertificatePins.CURRENT, CertificatePins.BACKUP)
                .build()
        )
    }
}
