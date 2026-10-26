// flutter_inappwebview v5's Android handler and a webview_flutter delegate that proceeds via a named function.
import 'package:flutter_inappwebview/flutter_inappwebview.dart';
import 'package:webview_flutter/webview_flutter.dart';

Widget checkout(Uri url) => InAppWebView(
      initialUrlRequest: URLRequest(url: url),
      androidOnReceivedServerTrustAuthRequest: (InAppWebViewController controller,
          URLAuthenticationChallenge challenge) async {
        debugPrint('TLS error on ${challenge.protectionSpace.host}');
        return ServerTrustAuthResponse(action: ServerTrustAuthResponseAction.PROCEED);
      },
    );

void _ignoreSslError(SslAuthError error) => error.proceed();

WebViewController paymentController() => WebViewController()
  ..setNavigationDelegate(NavigationDelegate(
    onPageFinished: (url) => debugPrint(url),
    onSslAuthError: _ignoreSslError,
  ));
