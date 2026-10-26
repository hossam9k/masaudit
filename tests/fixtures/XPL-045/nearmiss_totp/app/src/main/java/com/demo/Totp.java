package com.demo;

// A TOTP code is meant to come from the time: the secret key makes it unguessable, not the clock.
class TotpView {
    String code(TotpInfo info, int offset) {
        String otp = info.getOtp((System.currentTimeMillis() / 1000) + ((long) offset * info.getPeriod()));
        return otp;
    }
}
