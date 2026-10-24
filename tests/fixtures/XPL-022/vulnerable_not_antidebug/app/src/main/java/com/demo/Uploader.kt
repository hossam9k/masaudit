package com.demo

import android.os.Debug

fun shouldReport(): Boolean = !Debug.isDebuggerConnected()
