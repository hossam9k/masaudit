import 'package:encrypt/encrypt.dart';
import 'package:shared_preferences/shared_preferences.dart';

Future<void> createKey(SharedPreferences prefs) async {
  final key = Key.fromSecureRandom(32);
  await prefs.setString('db_key', key.base64);
}
