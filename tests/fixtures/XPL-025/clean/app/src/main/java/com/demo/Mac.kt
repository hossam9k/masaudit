package com.demo
fun verify(key: SecretKey, data: ByteArray, receivedMac: ByteArray): Boolean {
    val mac = Mac.getInstance("HmacSHA256").apply { init(key) }
    return MessageDigest.isEqual(mac.doFinal(data), receivedMac)
}
fun same(view: View, tag: String) = view.tag == tag
fun alg(mac: Mac) = mac.algorithm == "HmacSHA256"
