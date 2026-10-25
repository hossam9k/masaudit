package com.example.bank;

import java.io.IOException;
import java.net.Socket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class TlsServer {
    public SSLSocket upgrade(SSLSocketFactory factory, Socket plain) throws IOException {
        SSLSocket socket = (SSLSocket) factory.createSocket(plain, plain.getInetAddress().getHostAddress(),
                plain.getPort(), true);
        socket.setUseClientMode(false);
        socket.startHandshake();
        return socket;
    }
}
