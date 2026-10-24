package com.demo
fun send(session: Session) {
    Timber.i("Authorization: Bearer ${session.accessToken}")
}
