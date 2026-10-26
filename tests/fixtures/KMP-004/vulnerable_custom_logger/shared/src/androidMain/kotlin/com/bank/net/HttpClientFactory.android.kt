// Android engine with a Napier-backed logger object at LogLevel.ALL.
package com.bank.net

import io.github.aakira.napier.Napier
import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.plugins.logging.LogLevel
import io.ktor.client.plugins.logging.Logger
import io.ktor.client.plugins.logging.Logging

actual fun platformClient(): HttpClient = HttpClient(OkHttp) {
    install(Logging) {
        logger = object : Logger {
            override fun log(message: String) {
                Napier.d(message, tag = "HTTP")
            }
        }
        level = LogLevel.ALL
    }
}
