package com.shop
import io.ktor.client.HttpClient
import io.ktor.client.engine.darwin.Darwin

// TODO: CertificatePinner for Darwin
actual fun createPinnedHttpClient(): HttpClient = HttpClient(Darwin)
