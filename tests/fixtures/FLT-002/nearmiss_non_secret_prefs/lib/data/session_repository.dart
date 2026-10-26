// Only non-secret values go to shared_preferences; the tokens themselves go to secure storage.
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';

abstract final class PrefKeys {
  static const pushToken = 'push_token';
  static const lastEmail = 'last_login_email';
}

class SessionRepository {
  final _secure = const FlutterSecureStorage();

  Future<void> persist(Session session, String fcmToken) async {
    await _secure.write(key: 'access_token', value: session.accessToken);
    await _secure.write(key: 'refresh_token', value: session.refreshToken);
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(PrefKeys.pushToken, fcmToken);
    await prefs.setString(PrefKeys.lastEmail, session.email);
    await prefs.setString('token_expires_at', session.expiresAt.toIso8601String());
    await prefs.setBool('biometric_password_enabled', true);
    await prefs.setStringList('recent_searches', session.recentSearches);
  }
}
