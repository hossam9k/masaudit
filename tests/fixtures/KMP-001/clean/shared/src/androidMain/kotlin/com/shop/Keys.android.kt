package com.shop
actual suspend fun storeToken(token: String, requiringUserAuth: Boolean) { }
interface KeystoreProvider { fun key(): java.security.Key }
