package com.example.bank;

class LegacyAttest {
    void run(GoogleApiClient client, byte[] nonce) {
        SafetyNet.SafetyNetApi.attest(client, nonce);
    }
}
