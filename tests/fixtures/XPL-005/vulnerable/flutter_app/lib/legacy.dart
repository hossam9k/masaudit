import 'package:encrypt/encrypt.dart';

Encrypter legacy(Key key) => Encrypter(AES(key, mode: AESMode.cbc));
