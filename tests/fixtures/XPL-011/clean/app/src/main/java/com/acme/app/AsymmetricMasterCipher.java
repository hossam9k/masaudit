package com.acme.app;
class AsymmetricMasterCipher {
    private SecretKeySpec deriveMacKey(byte[] secretBytes) {
        byte[] digestedBytes = getDigestedBytes(secretBytes, 1);
        byte[] macKeyBytes   = new byte[20];
        System.arraycopy(digestedBytes, 0, macKeyBytes, 0, macKeyBytes.length);
        return new SecretKeySpec(macKeyBytes, "HmacSHA1");
    }
}
