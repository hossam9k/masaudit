package com.acme

// Shapes seen in Signal and Element: code that handles bidi characters by name.
private const val RLO = "‮"
private const val LRI = "⁦"
fun isInvisible(c: Char): Boolean = when (c) {
    in '‪'..'‮' -> true // bidi formatting overrides
    in '⁦'..'⁩' -> true // bidi isolate controls
    else -> false
}
fun sender(id: String) = "⁨" + id + "⁩: sent a sticker"
