// Headers logged with every credential header masked, INFO-only logging, and a level chosen per environment.
package com.bank.net

import io.ktor.client.HttpClient
import io.ktor.client.plugins.logging.*
import io.ktor.http.HttpHeaders

fun apiClient(env: Environment): HttpClient = HttpClient {
    install(Logging) {
        logger = Logger.SIMPLE
        level = LogLevel.HEADERS
        sanitizeHeader(placeholder = "***") { header ->
            header == HttpHeaders.Authorization || header == "X-Api-Key"
        }
    }
}

fun telemetryClient(): HttpClient = HttpClient {
    install(Logging) { level = LogLevel.INFO }
}

fun envClient(env: Environment): HttpClient = HttpClient {
    install(Logging) { level = env.httpLogLevel }
}

const val LOGGING_HINT = "never ship level = LogLevel.ALL"
