// Levels chosen at runtime: a conditional constant, a constructor parameter's default, and a function call.
package com.bank.net

import io.ktor.client.HttpClient
import io.ktor.client.plugins.logging.*

private val HTTP_LOG_LEVEL = if (Platform.isDebugBinary) LogLevel.ALL else LogLevel.NONE

class HttpConfig(val logLevel: LogLevel = LogLevel.ALL) {
    fun client() = HttpClient {
        install(Logging) {
            level = logLevel
        }
    }
}

fun createClient() = HttpClient {
    install(Logging) {
        level = HTTP_LOG_LEVEL
    }
}

fun verboseClient(verbose: Boolean) = HttpClient {
    install(Logging) {
        level = chooseLevel(verbose)
    }
}
