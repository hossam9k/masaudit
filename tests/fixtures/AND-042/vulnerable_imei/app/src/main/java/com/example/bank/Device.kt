package com.example.bank

import android.content.Context
import android.telephony.TelephonyManager

fun deviceKey(tm: TelephonyManager): String? = tm.getImei()

fun deviceKey2(context: Context): String? =
    (context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager).getImei()
