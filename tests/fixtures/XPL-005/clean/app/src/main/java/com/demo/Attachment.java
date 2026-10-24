package com.demo;
class Attachment {
    Cipher cipher() throws Exception { return Cipher.getInstance("AES/CBC/PKCS5Padding"); }
    Mac mac(SecretKey k) throws Exception { Mac m = Mac.getInstance("HmacSHA256"); m.init(k); return m; }
}
