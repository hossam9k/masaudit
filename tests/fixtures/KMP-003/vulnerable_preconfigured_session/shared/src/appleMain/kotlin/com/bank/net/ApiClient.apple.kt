// usePreconfiguredSession makes the Darwin engine ignore handleChallenge (book 8.10).
package com.bank.net

import io.ktor.client.HttpClient
import io.ktor.client.engine.darwin.Darwin
import io.ktor.client.engine.darwin.certificates.CertificatePinner
import platform.Foundation.NSURLSession
import platform.Foundation.NSURLSessionConfiguration

actual fun apiClient(): HttpClient = HttpClient(Darwin) {
    engine {
        usePreconfiguredSession(NSURLSession.sessionWithConfiguration(NSURLSessionConfiguration.defaultSessionConfiguration))
        handleChallenge(CertificatePinner.Builder().add("api.bank.example", *apiPins.toTypedArray()).build())
    }
}
