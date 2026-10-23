package com.demo;
import java.util.Random;
class Rng {
    Random r = new Random();
    double d = Math.random();
    SecureRandom s = new SecureRandom(seedBytes);
}
