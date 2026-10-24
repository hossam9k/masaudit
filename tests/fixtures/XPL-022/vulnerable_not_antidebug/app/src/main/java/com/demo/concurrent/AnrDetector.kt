package com.demo.concurrent

import android.os.Debug

class AnrDetector {
    fun check(uiRan: Boolean) {
        // Don't report an ANR while someone is stepping through code in a debugger.
        if (!uiRan && !Debug.isDebuggerConnected() && !Debug.waitingForDebugger()) {
            reportAnr()
        }
    }

    private fun reportAnr() {}
}
