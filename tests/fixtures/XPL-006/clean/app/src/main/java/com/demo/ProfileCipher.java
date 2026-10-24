package com.demo;
class ProfileCipher {
    byte[] encrypt(byte[] input) throws Exception {
        byte[] nonce = Util.getSecretBytes(12);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        return cipher.doFinal(input);
    }
    byte[] decrypt(byte[] input) throws Exception {
        byte[] nonce = new byte[12];
        System.arraycopy(input, 0, nonce, 0, nonce.length);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        return cipher.doFinal(input, 12, input.length - 12);
    }
}
