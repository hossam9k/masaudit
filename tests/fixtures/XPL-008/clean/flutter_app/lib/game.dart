import 'dart:math';

class GameSession {
  final _random = Random();
  Move pick(List<Move> m) => m[_random.nextInt(m.length)];
}
String makeNonce() {
  final random = Random.secure();
  return List.generate(16, (_) => random.nextInt(16).toRadixString(16)).join();
}
