package com.shop

import io.ktor.client.HttpClient
import io.ktor.client.plugins.logging.*

fun client() = HttpClient {
    install(Logging) {
        logger = Logger.DEFAULT
        level = LogLevel.HEADERS
    }
}

fun bodyClient() = HttpClient {
    install(Logging) {
        level = LogLevel.BODY
        sanitizeHeader { it == "Authorization" }
    }
}

fun debugClient(isDebug: Boolean) = HttpClient {
    if (isDebug) {
        install(Logging) { level = LogLevel.ALL }
    }
}
