import 'package:flutter_web_auth_2/flutter_web_auth_2.dart';

class OAuthService {
  final callbackUrlScheme = 'app.acmebank';

  Future<String> oAuthLogin(String oauthUrl) async {
    final result = await FlutterWebAuth2.authenticate(url: oauthUrl, callbackUrlScheme: callbackUrlScheme);
    return result;
  }

  Future<String> legacyLogin(String oauthUrl) =>
      FlutterWebAuth.authenticate(url: oauthUrl, callbackUrlScheme: 'acmelegacy');

  Future<String> universalLink(String oauthUrl) => FlutterWebAuth2.authenticate(
        url: oauthUrl,
        callbackUrlScheme: 'https',
        options: const FlutterWebAuth2Options(httpsHost: 'auth.acmebank.com', httpsPath: '/cb'),
      );
}
