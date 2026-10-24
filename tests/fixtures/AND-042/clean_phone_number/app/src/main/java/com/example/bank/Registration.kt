package com.example.bank

import android.telephony.TelephonyManager

// The phone number prefills registration: personal data (AND-033), not a hardware identifier.
fun prefillNumber(tm: TelephonyManager): String? = tm.getLine1Number()

fun prefillNumberKt(telephonyManager: TelephonyManager): String? = telephonyManager.line1Number
