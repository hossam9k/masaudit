import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';

const _storage = FlutterSecureStorage();

class AuthStore {
  Future<void> save(String accessToken, String fcmToken, DateTime expiry) async {
    await _storage.write(key: 'access_token', value: accessToken);
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('theme', 'dark');
    await prefs.setString('fcm_token', fcmToken);
    await prefs.setString('token_expiry', expiry.toIso8601String());
    await prefs.setBool('has_token', true);
    // await prefs.setString('access_token', accessToken);
  }
}
