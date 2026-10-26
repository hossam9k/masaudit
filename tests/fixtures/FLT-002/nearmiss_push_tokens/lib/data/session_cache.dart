// Push and device tokens, token expiry times, and values that end before a later token mention.
import 'dart:convert';

import 'package:shared_preferences/shared_preferences.dart';

class SessionCache {
  Future<void> save(Session s, Registration registration, String fcmToken) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('token', fcmToken);
    await prefs.setString('push', jsonEncode({'id': registration.id, 'token': registration.deviceToken}));
    await prefs.setString(
      'session_meta',
      jsonEncode({'user': s.userId, 'expires': s.tokenExpiresAt.toIso8601String()}),
    );
    await prefs.setString('locale', s.languageCode).then((_) => refreshToken());
  }
}
