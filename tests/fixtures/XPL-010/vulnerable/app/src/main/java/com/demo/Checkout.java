package com.demo;

import android.util.Log;
import android.widget.EditText;

public class Checkout {
    public void checkout(EditText cctxt) {
        try {
            processCC(cctxt.getText().toString());
        } catch (RuntimeException re) {
            Log.e("shop", "Error while processing transaction with credit card: " + cctxt.getText().toString());
        }
    }

    void pay(String cardNumber) {
        Log.d("shop", "paying with " + cardNumber);
    }

    void processCC(String number) {
    }
}
