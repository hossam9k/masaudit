// The level comes from a constant declared in the same file.
package com.bank.net

import io.ktor.client.HttpClient
import io.ktor.client.plugins.logging.*

private val HTTP_LOG_LEVEL = LogLevel.ALL

fun createClient() = HttpClient {
    install(Logging) {
        logger = Logger.DEFAULT
        level = HTTP_LOG_LEVEL
    }
}
