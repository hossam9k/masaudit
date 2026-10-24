package com.demo.crypto;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class MasterSecretUtil {
  // Times a fixed number of rounds to pick the real iteration count for this device.
  private static int generateIterationCount(String p, byte[] salt) throws Exception {
    int BENCHMARK_ITERATION_COUNT = 10000;
    PBEKeySpec ks = new PBEKeySpec(p.toCharArray(), salt, BENCHMARK_ITERATION_COUNT);
    SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
    long t0 = System.currentTimeMillis(); skf.generateSecret(ks); long t1 = System.currentTimeMillis();
    return (int) (BENCHMARK_ITERATION_COUNT / (t1 - t0 + 1)) * 50;
  }

  private static int timeRounds(String p, byte[] salt) throws Exception {
    PBEKeySpec spec = new PBEKeySpec(p.toCharArray(), salt, 5000);
    long start = System.nanoTime();
    SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").generateSecret(spec);
    return (int) (System.nanoTime() - start);
  }
}
