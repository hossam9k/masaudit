package com.demo;
class Itunes {
    public static final String NSURI = "http://www.itunes.com/dtds/podcast-1.0.dtd";
    public static final String MEDIA_NSURI = "http://search.yahoo.com/mrss/";
    boolean ok(String host) { return HttpUrl.parse("http://[" + host + "]/") != null; }
}
