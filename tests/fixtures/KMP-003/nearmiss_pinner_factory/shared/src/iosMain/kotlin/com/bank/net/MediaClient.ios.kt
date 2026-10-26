// A separate public-CDN client on a preconfigured session; it carries no pins, so it does not affect the API client.
package com.bank.net

import io.ktor.client.HttpClient
import io.ktor.client.engine.darwin.Darwin
import platform.Foundation.NSURLSession

fun mediaClient(session: NSURLSession): HttpClient = HttpClient(Darwin) {
    engine { usePreconfiguredSession(session) }
}
