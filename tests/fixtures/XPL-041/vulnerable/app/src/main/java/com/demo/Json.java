package com.demo;
class Json {
    ObjectMapper mapper() { ObjectMapper m = new ObjectMapper(); m.enableDefaultTyping(); return m; }
    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS) static abstract class Payload {}
}
