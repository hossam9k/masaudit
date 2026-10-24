package com.demo;
class EncryptedCoder {
    OutputStream open(byte[] masterKey, File file) throws Exception {
        byte[] random = Util.getSecretBytes(32);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(masterKey, "HmacSHA256"));
        byte[] iv  = new byte[16];
        byte[] key = mac.doFinal(random);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return null;
    }
}
