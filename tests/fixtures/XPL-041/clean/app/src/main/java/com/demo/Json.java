package com.demo;
class Json {
    @JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type")
    @JsonSubTypes({@JsonSubTypes.Type(value = Card.class, name = "card")})
    static abstract class Payload {}
}
