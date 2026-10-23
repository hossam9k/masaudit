package com.demo
const val BASE_URL = "https://api.demo-shop.com/v1/"
const val EMULATOR = "http://10.0.2.2:8080/"
const val LOCAL = "http://localhost:3000"
val ns = "http://schemas.android.com/apk/res/android"
val doc = "http://www.example.com/sample"
fun isPlain(u: String) = u.startsWith("http://")
// const val OLD_URL = "http://api.demo-shop.com/v1/"
