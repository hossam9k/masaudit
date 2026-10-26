// commonMain uses multiplatform androidx and crypto libraries; the JDK digest lives behind expect/actual.
package com.bank.attest

import androidx.datastore.preferences.core.Preferences
import androidx.lifecycle.ViewModel
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.SHA256
import com.bank.platform.security.PlatformInfo

// Implemented with java.security.MessageDigest in jvmMain.
expect fun sha256(data: ByteArray): ByteArray

class HashViewModel : ViewModel() {
    private val hasher = CryptographyProvider.Default.get(SHA256).hasher()
    val label = "uses javax.crypto on Android"

    suspend fun hash(data: ByteArray): ByteArray = hasher.hash(data)
}
