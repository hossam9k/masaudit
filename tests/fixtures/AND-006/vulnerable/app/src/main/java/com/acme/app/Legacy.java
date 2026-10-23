package com.acme.app;

class Legacy {
    SSLContext ctx() throws Exception {
        return SSLContext.getInstance("TLSv1");
    }
}
