package com.acme.app

fun args(generated: String) = Bundle().also { it.putString(KEY_PASSWORD, generated) }

private const val KEY_PASSWORD = "password"
