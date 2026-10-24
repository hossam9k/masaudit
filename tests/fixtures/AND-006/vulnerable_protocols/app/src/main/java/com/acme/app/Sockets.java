package com.acme.app;

class Sockets {
    void harden(SSLSocket s) {
        s.setEnabledProtocols(new String[] { "TLSv1", "TLSv1.2" });
        s.setEnabledCipherSuites(new String[] { "SSL_RSA_WITH_RC4_128_SHA" });
    }
}
