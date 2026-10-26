// Android pinner factory, separate from the client.
package com.bank.net

import okhttp3.CertificatePinner

internal fun okHttpPinner(): CertificatePinner = CertificatePinner.Builder().add(Pins.HOST, *Pins.ALL).build()
