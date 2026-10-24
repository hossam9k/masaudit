# -dontobfuscate would turn renaming off
-keep class com.example.bank.model.** { *; }
-keep class com.example.bank.network.dto.** { *; }
-keep @androidx.annotation.Keep class *
-keep class * implements android.os.Parcelable { *; }
-keep,allowobfuscation class com.example.bank.** { *; }
-keepclassmembers class com.example.bank.security.RootDetector { native <methods>; }
