package com.demo;

import org.apache.http.client.methods.HttpPost;

public class DoLogin {
    String serverip = "";
    String serverport = "";
    String protocol = "http://";

    public HttpPost login() {
        return new HttpPost(protocol + serverip + ":" + serverport + "/login");
    }
}
