package com.example.bank

import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

class VerifiedTls {
    fun open(host: String): SSLSocket {
        val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
        val socket = factory.createSocket(host, 443) as SSLSocket
        socket.startHandshake()
        if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(host, socket.session)) {
            socket.close()
            throw SSLPeerUnverifiedException("Certificate doesn't match $host")
        }
        return socket
    }
}
