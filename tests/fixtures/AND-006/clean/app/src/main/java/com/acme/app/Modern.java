package com.acme.app;

class Modern {
    SSLContext a() throws Exception { return SSLContext.getInstance("TLS"); }
    SSLContext b() throws Exception { return SSLContext.getInstance("TLSv1.2"); }
}
