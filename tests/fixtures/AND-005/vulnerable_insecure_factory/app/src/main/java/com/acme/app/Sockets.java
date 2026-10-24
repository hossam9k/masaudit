package com.acme.app;

class Sockets {
    SSLSocketFactory factory() {
        return SSLCertificateSocketFactory.getInsecure(0, null);
    }
}
