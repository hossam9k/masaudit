package com.acme.app;

import javax.crypto.spec.SecretKeySpec;

class Legacy {
    private static final byte[] KEY = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    SecretKeySpec key() { return new SecretKeySpec(KEY, "AES"); }
}
