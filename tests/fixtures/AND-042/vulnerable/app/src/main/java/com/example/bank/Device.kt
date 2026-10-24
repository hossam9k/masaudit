package com.example.bank

class Device(private val context: Context, private val telephonyManager: TelephonyManager) {
    fun androidId(): String = Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
    fun imei(): String? = telephonyManager.imei
    fun serial(): String = Build.getSerial()
    fun mac(wifiInfo: WifiInfo): String = wifiInfo.macAddress
}
