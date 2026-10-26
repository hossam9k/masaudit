// A token inside a JSON-encoded value (one line and several), and an API key read from a device object.
import 'dart:convert';

import 'package:shared_preferences/shared_preferences.dart';

class SessionCache {
  Future<void> save(Session s, DeviceRegistration deviceRegistration) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('session', jsonEncode({'user': s.userId, 'token': s.refreshToken}));
    await prefs.setString(
      'auth',
      jsonEncode({
        'expiresAt': s.expiresAt.toIso8601String(),
        'access': s.accessToken,
      }),
    );
    await prefs.setString('api_key', deviceRegistration.apiKey);
  }
}
