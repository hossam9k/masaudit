// PROCEED is returned only when the server certificate matches the pinned fingerprint; SSL errors cancel.
import 'package:crypto/crypto.dart';
import 'package:flutter_inappwebview/flutter_inappwebview.dart';
import 'package:webview_flutter/webview_flutter.dart';

const pinnedFingerprint = 'replace-with-sha256-of-leaf-der';

Future<ServerTrustAuthResponse?> _verify(InAppWebViewController c, URLAuthenticationChallenge ch) async {
  final der = ch.protectionSpace.sslCertificate?.x509Certificate?.encoded;
  final ok = der != null && sha256.convert(der).toString() == pinnedFingerprint;
  return ServerTrustAuthResponse(
    action: ok ? ServerTrustAuthResponseAction.PROCEED : ServerTrustAuthResponseAction.CANCEL,
  );
}

Widget checkout(Uri url) => InAppWebView(
      initialUrlRequest: URLRequest(url: url),
      onReceivedServerTrustAuthRequest: _verify,
    );

final delegate = NavigationDelegate(onSslAuthError: (error) async {
  await error.cancel();
});
