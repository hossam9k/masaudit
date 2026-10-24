package com.demo

import java.net.Socket
import javax.crypto.Mac
import javax.crypto.SecretKey

fun readSigned(socket: Socket, key: SecretKey): ByteArray? {
    val body = socket.getInputStream().readNBytes(256)
    val receivedMac = socket.getInputStream().readNBytes(32)
    val expectedMac = Mac.getInstance("HmacSHA256").apply { init(key) }.doFinal(body)
    return if (expectedMac.contentEquals(receivedMac)) body else null
}
