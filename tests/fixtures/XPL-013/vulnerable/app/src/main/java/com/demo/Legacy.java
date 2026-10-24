package com.demo;
class Legacy {
    Cipher des() throws Exception { return Cipher.getInstance("DES/ECB/PKCS5Padding"); }
    Cipher tdes() throws Exception { return Cipher.getInstance("DESede/CBC/PKCS5Padding"); }
    Cipher rc4() throws Exception { return Cipher.getInstance("RC4"); }
    SecretKeyFactory pbe() throws Exception { return SecretKeyFactory.getInstance("PBEWithMD5AndDES"); }
}
