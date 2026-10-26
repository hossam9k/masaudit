// commonMain reaching for Play Integrity, App Attest, wildcard javax.crypto, an aliased import, and keystore constants.
package com.bank.attest

import com.google.android.play.core.integrity.IntegrityManagerFactory
import platform.DeviceCheck.DCAppAttestService
import javax.crypto.*
import java.security.MessageDigest as JDigest
import android.security.keystore.KeyProperties
import kotlinx.coroutines.flow.Flow

class Attestation(private val nonce: ByteArray) {
    fun digest(): ByteArray = JDigest.getInstance("SHA-256").digest(nonce)

    fun aesKey(): SecretKey = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES).generateKey()

    fun appAttestSupported(): Boolean = DCAppAttestService.sharedService.isSupported()
}
