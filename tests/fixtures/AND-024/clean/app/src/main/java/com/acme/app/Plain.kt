package com.acme.app

// No master key on purpose: the threat model excludes device compromise.
fun plain(context: Context) = AndroidKeysetManager.Builder()
    .withSharedPref(context, "flags_keyset", "tink_keysets")
    .build()
