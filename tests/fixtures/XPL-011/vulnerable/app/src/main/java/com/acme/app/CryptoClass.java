package com.acme.app;

import android.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptoClass {
    String key = "This is the super secret key 123";
    byte[] ivBytes = new byte[16];

    public static byte[] aes256encrypt(byte[] ivBytes, byte[] keyBytes, byte[] textBytes) throws Exception {
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        SecretKeySpec newKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, newKey, ivSpec);
        return cipher.doFinal(textBytes);
    }

    public String aesEncryptedString(String theString) throws Exception {
        byte[] keyBytes = key.getBytes("UTF-8");
        byte[] cipherData = CryptoClass.aes256encrypt(ivBytes, keyBytes, theString.getBytes("UTF-8"));
        return Base64.encodeToString(cipherData, Base64.DEFAULT);
    }
}
