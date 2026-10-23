import 'package:encrypt/encrypt.dart';
import 'package:pointycastle/export.dart';

Encrypted seal(Key key, String text) {
  final encrypter = Encrypter(AES(key, mode: AESMode.ecb));
  return encrypter.encrypt(text);
}

BlockCipher legacy() => ECBBlockCipher(AESEngine());
final cipher = BlockCipher('AES/ECB');
