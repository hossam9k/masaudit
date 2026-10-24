import 'package:pointycastle/export.dart';

Pbkdf2Parameters params(Uint8List salt) => Pbkdf2Parameters(salt, 600000, 32);
