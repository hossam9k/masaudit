// The client file only references the helper.
package com.bank.net

import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp

actual fun apiClient(): HttpClient = HttpClient(OkHttp) {
    engine { config { certificatePinner(okHttpPinner()) } }
}
