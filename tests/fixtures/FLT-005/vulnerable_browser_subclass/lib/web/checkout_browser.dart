// An InAppBrowser subclass whose override accepts every server certificate.
import 'package:flutter_inappwebview/flutter_inappwebview.dart';

class CheckoutBrowser extends InAppBrowser {
  @override
  Future<ServerTrustAuthResponse?> onReceivedServerTrustAuthRequest(URLAuthenticationChallenge challenge) async {
    return ServerTrustAuthResponse(action: ServerTrustAuthResponseAction.PROCEED);
  }
}
