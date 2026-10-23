package com.acme.app

import okhttp3.OkHttpClient

// TODO: add certificate pinning before launch.
// val pinner = CertificatePinner.Builder().add("api.example.com", "sha256/YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=").build()
val client = OkHttpClient.Builder().build()
val status = "pinning: off"
