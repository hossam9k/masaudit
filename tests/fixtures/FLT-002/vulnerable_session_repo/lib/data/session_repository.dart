// Keys from a constants class, a multi-line call, a value read from a JSON map, and the async API.
import 'package:shared_preferences/shared_preferences.dart';

abstract final class PrefKeys {
  static const authToken = 'auth_token';
}

class SessionRepository {
  final _async = SharedPreferencesAsync();

  Future<void> persist(Session session, String password) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(
      PrefKeys.authToken,
      session.accessToken,
    );
    await prefs.setString('jwt', session.raw['jwt'] as String);
    await _async.setString('remembered_password', password);
  }
}
