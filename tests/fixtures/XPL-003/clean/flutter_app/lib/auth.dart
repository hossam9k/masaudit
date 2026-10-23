class OAuthConfig {
  static const String clientSecret = String.fromEnvironment('CLIENT_SECRET');
  static const apiSecretKeyName = 'api_secret';
  final body = {'client_secret': '${secretFromServer}'};
  // static const String clientSecret = 'q8Lr2Vt6Yx1Nc4Bm7Ka9';
  final placeholder = {'app_secret': 'your-app-secret-here'};
}
