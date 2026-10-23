package com.acme.app

import javax.crypto.spec.SecretKeySpec

private const val AES_KEY = "k3y-th4t-sh1ps-1n-th3-apk"

object Crypto {
    val inline = SecretKeySpec("0123456789abcdef".toByteArray(), "AES")
    val fromConstant = SecretKeySpec(AES_KEY.toByteArray(), "AES")
    val fromBase64 = SecretKeySpec(java.util.Base64.getDecoder().decode("q83vEjRWeJA="), "AES")
}
