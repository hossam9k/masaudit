package com.acme.app;

class State extends Activity {
    @Override
    protected void onSaveInstanceState(Bundle outState) {
        outState.putString("password", password);
    }
    Bundle authResult(String token) {
        Bundle result = new Bundle();
        result.putString(AccountManager.KEY_AUTHTOKEN, token);
        return result;
    }
}
