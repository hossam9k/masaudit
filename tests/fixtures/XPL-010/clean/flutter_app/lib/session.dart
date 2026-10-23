import 'dart:developer' as developer;

import 'package:flutter/foundation.dart';

void onLogin(String accessToken, String userId) {
  print('Token refreshed');
  debugPrint('Signed in as $userId');
  developer.log('login ok', name: 'auth');
  // print('token: $accessToken');
}
