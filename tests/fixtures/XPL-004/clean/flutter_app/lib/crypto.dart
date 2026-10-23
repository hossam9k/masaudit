import 'package:encrypt/encrypt.dart';

// final encrypter = Encrypter(AES(key, mode: AESMode.ecb));
const label = 'AESMode.ecb is unsafe';

Encrypted seal(Key key, IV iv, String text) {
  final encrypter = Encrypter(AES(key, mode: AESMode.gcm));
  return encrypter.encrypt(text, iv: iv);
}
