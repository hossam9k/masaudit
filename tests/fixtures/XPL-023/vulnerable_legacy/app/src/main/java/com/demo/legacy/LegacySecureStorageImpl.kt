package com.demo.legacy

import java.security.Key
import javax.crypto.Cipher

class LegacySecureStorageImpl {
    private fun wrapKey(keyToWrap: Key, withKey: Key): ByteArray {
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.WRAP_MODE, withKey)
        return cipher.wrap(keyToWrap)
    }
}
