package com.demo;

public class ServerInput {
    public static final String HTTP_PROTOCOL = "http://";
    public static final String HTTPS_PROTOCOL = "https://";

    // Rejects a plain-HTTP address the user typed; nothing is fetched from it.
    public boolean isInsecure(String url) {
        return url.toLowerCase().startsWith(HTTP_PROTOCOL);
    }

    public String secure(String host) {
        return HTTPS_PROTOCOL + host;
    }
}
