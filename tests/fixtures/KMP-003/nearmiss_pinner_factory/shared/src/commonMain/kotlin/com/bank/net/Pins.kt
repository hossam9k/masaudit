// Pins shared in commonMain; both engines enforce them, the Android pinner is built in a helper file.
package com.bank.net

import io.ktor.client.HttpClient

object Pins {
    const val HOST = "api.bank.example"
    val ALL = arrayOf("sha256/YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=", "sha256/Vjs8r4z+80wjNcr1YKepWQboSIRi63WsWXhIMN+eWys=")
}

expect fun apiClient(): HttpClient
