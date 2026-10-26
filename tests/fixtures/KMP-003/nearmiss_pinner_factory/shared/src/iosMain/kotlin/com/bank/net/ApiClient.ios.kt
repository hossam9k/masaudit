// Darwin enforces the same pins through handleChallenge on Ktor's own session.
package com.bank.net

import io.ktor.client.HttpClient
import io.ktor.client.engine.darwin.Darwin
import io.ktor.client.engine.darwin.certificates.CertificatePinner

actual fun apiClient(): HttpClient = HttpClient(Darwin) {
    engine {
        handleChallenge(CertificatePinner.Builder().add(Pins.HOST, *Pins.ALL).build())
    }
}
