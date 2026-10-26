// Platform source set: naming the mechanism here is fine.
package com.bank.security

interface AndroidKeystoreProvider {
    fun keyFor(alias: String): java.security.Key
}
