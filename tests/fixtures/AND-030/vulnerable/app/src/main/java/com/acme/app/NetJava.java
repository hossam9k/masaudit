package com.acme.app;

class NetJava {
    void setup(HttpLoggingInterceptor logging) {
        logging.setLevel(HttpLoggingInterceptor.Level.BODY);
    }
}
