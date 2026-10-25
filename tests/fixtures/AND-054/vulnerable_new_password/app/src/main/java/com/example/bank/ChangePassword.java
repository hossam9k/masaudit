package com.example.bank;

import android.app.Activity;
import android.content.Intent;

public class ChangePassword extends Activity {
    void broadcastChange(String phoneNumber, String pass) {
        Intent smsIntent = new Intent();
        smsIntent.setAction("theBroadcast");
        smsIntent.putExtra("phonenumber", phoneNumber);
        smsIntent.putExtra("newpass", pass);
        sendBroadcast(smsIntent);
    }
}
