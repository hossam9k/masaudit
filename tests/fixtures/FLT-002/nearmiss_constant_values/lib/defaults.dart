// Constant settings under token-like keys: nothing secret is stored.
import 'package:shared_preferences/shared_preferences.dart';

Future<void> saveDefaults(SharedPreferences prefs) async {
  await prefs.setString('token_type', 'Bearer');
  await prefs.setString('password_policy_version', '3');
  await prefs.setString('auth_token', '');
}
