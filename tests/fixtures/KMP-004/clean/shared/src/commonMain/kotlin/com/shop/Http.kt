package com.shop

import io.ktor.client.HttpClient
import io.ktor.client.plugins.logging.*
import io.ktor.http.HttpHeaders

fun client(isDebug: Boolean, config: Config) = HttpClient {
    install(Logging) { level = LogLevel.INFO }
    install(Logging) { level = if (isDebug) LogLevel.ALL else LogLevel.NONE }
    install(Logging) {
        level = LogLevel.HEADERS
        sanitizeHeader { header -> header == HttpHeaders.Authorization }
    }
    install(Logging) { level = config.logLevel }
    // install(Logging) { level = LogLevel.ALL }
}
