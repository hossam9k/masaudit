package com.shop
import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp

// No CertificatePinner: the pins live in res/xml/network_security_config.xml, which Android enforces.
actual fun createPinnedHttpClient(): HttpClient = HttpClient(OkHttp)
