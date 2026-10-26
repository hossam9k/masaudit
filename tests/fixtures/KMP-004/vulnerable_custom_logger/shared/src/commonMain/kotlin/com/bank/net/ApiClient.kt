// Shared client: the block opens on the next line, uses `this.level`, and filters requests but does not sanitize headers.
package com.bank.net

import io.ktor.client.HttpClient
import io.ktor.client.plugins.logging.*

expect fun platformClient(): HttpClient

fun apiClient(): HttpClient = HttpClient {
    install(Logging)
    {
        logger = Logger.SIMPLE
        this.level = LogLevel.HEADERS
        filter { request -> request.url.host.endsWith("bank.example") }
    }
}
