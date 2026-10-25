package com.demo;

import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class HelperIv {
    public byte[] decrypt(byte[] keyBytes, byte[] data) throws Exception {
        final byte[] ivBytes = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        return HelperIv.aes256decrypt(ivBytes, keyBytes, data);
    }

    public static byte[] aes256decrypt(byte[] iv, byte[] keyBytes, byte[] textBytes)
            throws java.io.UnsupportedEncodingException,
            java.security.GeneralSecurityException {
        AlgorithmParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec newKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, newKey, ivSpec);
        return cipher.doFinal(textBytes);
    }
}
