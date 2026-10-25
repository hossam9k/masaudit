package com.acme.app;

import android.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class CryptoClass {
    String keyAlias = "vault";

    public static byte[] aes256encrypt(byte[] keyBytes, byte[] textBytes) throws Exception {
        SecretKeySpec newKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, newKey);
        return cipher.doFinal(textBytes);
    }

    public String encrypt(String theString, KeyStoreHelper store) throws Exception {
        byte[] keyBytes = store.unwrap(keyAlias);
        byte[] cipherData = CryptoClass.aes256encrypt(keyBytes, theString.getBytes("UTF-8"));
        return Base64.encodeToString(cipherData, Base64.DEFAULT);
    }

    interface KeyStoreHelper {
        byte[] unwrap(String alias);
    }
}
