import 'package:flutter_inappwebview/flutter_inappwebview.dart';
import 'package:webview_flutter/webview_flutter.dart';

Widget a() => InAppWebView(
      onReceivedServerTrustAuthRequest: (controller, challenge) async {
        return ServerTrustAuthResponse(action: ServerTrustAuthResponseAction.PROCEED);
      },
    );

Widget b() => InAppWebView(
      onReceivedServerTrustAuthRequest: (c, ch) async =>
          ServerTrustAuthResponse(action: ServerTrustAuthResponseAction.PROCEED),
    );

final delegate = NavigationDelegate(onSslAuthError: (error) {
  error.proceed();
});

Widget c() => InAppWebView(onReceivedServerTrustAuthRequest: _trustAll);

Future<ServerTrustAuthResponse?> _trustAll(InAppWebViewController c, URLAuthenticationChallenge ch) async {
  return ServerTrustAuthResponse(action: ServerTrustAuthResponseAction.PROCEED);
}
