// An InAppBrowser subclass whose override proceeds only for a pinned certificate.
import 'package:crypto/crypto.dart';
import 'package:flutter_inappwebview/flutter_inappwebview.dart';

class CheckoutBrowser extends InAppBrowser {
  static const _pins = {'pinned-leaf-fingerprint'};

  @override
  Future<ServerTrustAuthResponse?> onReceivedServerTrustAuthRequest(URLAuthenticationChallenge challenge) async {
    final der = challenge.protectionSpace.sslCertificate?.x509Certificate?.encoded;
    if (der != null && _pins.contains(sha256.convert(der).toString())) {
      return ServerTrustAuthResponse(action: ServerTrustAuthResponseAction.PROCEED);
    }
    return ServerTrustAuthResponse(action: ServerTrustAuthResponseAction.CANCEL);
  }
}
