package com.demo;
class Enc {
    void a(SecretKey k) throws Exception {
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        c.init(Cipher.ENCRYPT_MODE, k, new GCMParameterSpec(128, nonce));
    }
}
