// Fully qualified platform classes from sub-packages, without imports, in shared code.
package com.bank.keys

class KeyFactory {
    fun spec(alias: String) = android.security.keystore.KeyGenParameterSpec.Builder(alias, 3).build()

    fun publicKey(b: ByteArray) = java.security.spec.X509EncodedKeySpec(b)
}
