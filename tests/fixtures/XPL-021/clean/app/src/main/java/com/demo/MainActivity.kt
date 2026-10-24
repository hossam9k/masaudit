package com.demo
class MainActivity : AppCompatActivity()
fun rooted() = File("/system/xbin/su").exists() || RootBeer(ctx).isRooted
