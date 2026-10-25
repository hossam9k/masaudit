package com.demo;

import android.widget.EditText;

public class DoLogin {
    boolean devLogin(String username, String password) {
        if (username.equals("devadmin")) {
            return true;
        }
        return false;
    }

    boolean vendorKey(EditText hckey) {
        return hckey.getText().toString().equals("vendorsecretkey");
    }
}
