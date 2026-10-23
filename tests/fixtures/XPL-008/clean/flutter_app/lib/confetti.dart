import 'dart:math';

// Animation jitter: no security value, so dart:math Random is fine here.
double jitter() => Random().nextDouble() * 4;
