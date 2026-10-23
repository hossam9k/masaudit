import 'package:shared_preferences/shared_preferences.dart';

const _refreshKey = 'refresh_token';

class AuthStore {
  Future<void> save(String accessToken, String refresh, String password) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('access_token', accessToken);
    await prefs.setString(_refreshKey, refresh);
    await prefs.setString('user_pw', password);
    await prefs.setStringList('api_keys', <String>[accessToken]);
  }
}
