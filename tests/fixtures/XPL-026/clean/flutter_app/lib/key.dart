import 'package:encrypt/encrypt.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

Future<void> createKey(FlutterSecureStorage storage) async {
  final key = Key.fromSecureRandom(32);
  await storage.write(key: 'db_key', value: key.base64);
}
