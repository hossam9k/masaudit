package com.acme.app

class NotificationsSheet : BottomSheetDialogFragment() {
    fun open() {
        startActivity(BundleCompat.getParcelable(requireArguments(), ARG_SETTINGS_INTENT, Intent::class.java)!!)
    }
}
