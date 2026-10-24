package com.example.bank;

class Handoff extends Activity {
    static final String ACTION_HANDOFF = "com.partner.HANDOFF";
    void go(String password) {
        Intent i = new Intent(ACTION_HANDOFF);
        i.putExtra("password", password);
        startActivity(i);
    }
}
