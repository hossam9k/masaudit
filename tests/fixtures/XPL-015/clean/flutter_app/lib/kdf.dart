import 'package:cryptography/cryptography.dart';

final pbkdf2 = Pbkdf2(macAlgorithm: Hmac.sha256(), iterations: 600000, bits: 256);
