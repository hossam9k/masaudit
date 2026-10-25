package com.wallet;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import java.io.File;
import java.nio.file.Files;

public class DebugModule extends ReactContextBaseJavaModule {
  DebugModule(ReactApplicationContext c) { super(c); }
  @Override public String getName() { return "DebugModule"; }

  @ReactMethod
  public void readInternalFile(String path, Promise promise) {
    try {
      byte[] bytes = Files.readAllBytes(new File(path).toPath());
      promise.resolve(new String(bytes));
    } catch (Exception e) { promise.reject("READ_ERROR", e); }
  }
}
