# Release rules
-dontobfuscate
-keep class com.example.bank.** { *; }
-keep class * { *; }
-keepnames class com.example.bank.security.RootDetector
