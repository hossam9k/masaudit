import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:pointycastle/export.dart';

String passwordHash(String password) => md5.convert(utf8.encode(password)).toString();
String fingerprint(List<int> bytes) => sha1.convert(bytes).toString();
final digest = Digest('SHA-1');
