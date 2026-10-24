package com.demo
fun rooted() = File("/system/xbin/su").exists() || RootBeer(ctx).isRooted
