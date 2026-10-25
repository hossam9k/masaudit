package com.demo;

import android.util.Log;

public class Checkout {
    public void checkout(String cardNumber) {
        try {
            processCC(cardNumber);
        } catch (RuntimeException re) {
            Log.e("shop", "Error while processing transaction with credit card: " + re.getMessage());
            Log.d("shop", "card number length " + cardNumber.length());
            Log.d("shop", "SD card path: " + System.getenv("EXTERNAL_STORAGE"));
        }
    }

    void processCC(String number) {
    }
}
