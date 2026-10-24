import 'package:encrypt/encrypt.dart';

final encrypter = Encrypter(RSA(publicKey: publicKey, encoding: RSAEncoding.OAEP));
