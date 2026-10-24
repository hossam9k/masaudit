package com.demo;
class Modern {
    static final String DESCRIPTION = "DES is retired";
    Cipher gcm() throws Exception { return Cipher.getInstance("AES/GCM/NoPadding"); }
    String desc() { return DESCRIPTION; }
    // Cipher.getInstance("DES")
}
