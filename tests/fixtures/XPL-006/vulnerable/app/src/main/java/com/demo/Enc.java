package com.demo;
class Enc {
    private static final byte[] NONCE = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
    void a(SecretKey k) throws Exception { c.init(Cipher.ENCRYPT_MODE, k, new GCMParameterSpec(128, NONCE)); }
}
