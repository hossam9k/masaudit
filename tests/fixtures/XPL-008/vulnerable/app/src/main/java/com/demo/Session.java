package com.demo;
import java.util.Random;
class Session {
    String sessionId = Long.toHexString(new Random().nextLong());
}
