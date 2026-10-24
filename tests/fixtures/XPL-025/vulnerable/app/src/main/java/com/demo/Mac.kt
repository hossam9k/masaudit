package com.demo
fun verify(key: SecretKey, data: ByteArray, receivedMac: ByteArray): Boolean {
    val mac = Mac.getInstance("HmacSHA256").apply { init(key) }
    val expectedMac = mac.doFinal(data)
    return expectedMac.contentEquals(receivedMac)
}
fun verify2(expectedTag: ByteArray, tag: ByteArray) = java.util.Arrays.equals(expectedTag, tag)
