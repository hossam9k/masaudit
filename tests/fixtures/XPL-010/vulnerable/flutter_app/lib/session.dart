import 'dart:developer' as developer;

import 'package:flutter/foundation.dart';

void onLogin(String accessToken, String password) {
  print('Signed in with $accessToken');
  debugPrint('password: ${password}');
  developer.log('refresh', error: accessToken);
}
