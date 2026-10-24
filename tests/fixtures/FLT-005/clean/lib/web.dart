import 'package:flutter_inappwebview/flutter_inappwebview.dart';
import 'package:webview_flutter/webview_flutter.dart';

Widget a() => InAppWebView(
      onReceivedServerTrustAuthRequest: (controller, challenge) async {
        if (await pinMatches(challenge.protectionSpace.sslCertificate)) {
          return ServerTrustAuthResponse(action: ServerTrustAuthResponseAction.PROCEED);
        }
        return ServerTrustAuthResponse(action: ServerTrustAuthResponseAction.CANCEL);
      },
    );

Widget b() => InAppWebView(
      onReceivedServerTrustAuthRequest: (c, ch) async =>
          ServerTrustAuthResponse(action: ServerTrustAuthResponseAction.CANCEL),
    );

final delegate = NavigationDelegate(onSslAuthError: (error) => error.cancel());
