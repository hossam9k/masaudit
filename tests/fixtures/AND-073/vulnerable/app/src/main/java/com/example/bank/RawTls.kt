package com.example.bank

import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

class RawTls {
    fun fetch(host: String): String {
        val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
        val socket = factory.createSocket(host, 443) as SSLSocket
        socket.startHandshake()
        socket.outputStream.write("GET / HTTP/1.1\r\nHost: $host\r\n\r\n".toByteArray())
        return socket.inputStream.bufferedReader().readText()
    }
}
