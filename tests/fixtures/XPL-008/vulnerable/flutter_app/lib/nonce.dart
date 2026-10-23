import 'dart:math';

String makeNonce() {
  final random = Random();
  return List.generate(16, (_) => random.nextInt(16).toRadixString(16)).join();
}

final seeded = Random(42);
