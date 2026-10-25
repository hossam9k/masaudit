package com.example.bank;

import android.app.Activity;
import android.content.Intent;
import android.widget.RadioButton;

public class AccessControl extends Activity {
    public void viewCredentials(RadioButton registerNow) {
        Intent i = new Intent();
        boolean chk_pin = registerNow.isChecked();
        i.setAction("com.example.bank.action.VIEW_CREDS");
        i.putExtra(getString(R.string.chk_pin), chk_pin);
        i.putExtra("require_pin", true);
        i.putExtra("passed_username", "demo");
        startActivity(i);
    }
}
