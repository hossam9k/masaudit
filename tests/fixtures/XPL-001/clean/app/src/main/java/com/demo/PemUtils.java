package com.demo;
class PemUtils {
    String strip(String keyString) {
        return keyString.replaceAll("\\n", "").replace("-----BEGIN PRIVATE KEY-----", "");
    }
    String toPem(String privateKeyString) {
        return "-----BEGIN PRIVATE KEY-----\n" + privateKeyString + "\n-----END PRIVATE KEY-----";
    }
}
