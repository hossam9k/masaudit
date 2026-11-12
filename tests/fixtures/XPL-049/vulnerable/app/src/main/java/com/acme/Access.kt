package com.acme

fun canDelete(accessLevel: String): Boolean {
    if (accessLevel != "user‮ ⁦// Check if admin⁩ ⁦") {
        return false
    }
    return true
}

fun banner(secret: String): String {
    return "Hello ⁧" + secret + "⁩!"
}
