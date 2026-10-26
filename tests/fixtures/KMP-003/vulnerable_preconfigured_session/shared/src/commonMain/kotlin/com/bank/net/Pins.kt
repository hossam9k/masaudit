// Pins shared as a list; iOS hands Ktor its own session, so the handleChallenge pinner never runs.
package com.bank.net

import io.ktor.client.HttpClient

val apiPins = listOf(
    "sha256/YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=",
    "sha256/Vjs8r4z+80wjNcr1YKepWQboSIRi63WsWXhIMN+eWys=",
)

expect fun apiClient(): HttpClient
