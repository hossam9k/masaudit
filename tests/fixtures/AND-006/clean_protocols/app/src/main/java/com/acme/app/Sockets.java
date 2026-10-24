package com.acme.app;

class Sockets {
    void harden(SSLSocket s) {
        s.setEnabledProtocols(new String[] { "TLSv1.2", "TLSv1.3" });
        s.setEnabledCipherSuites(new String[] { "TLS_AES_128_GCM_SHA256", "TLS_RSA_WITH_3DES_EDE_CBC_SHA" });
    }
}
