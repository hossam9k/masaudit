import 'package:flutter_inappwebview/flutter_inappwebview.dart';

Widget helpPage() => InAppWebView(
      initialSettings: InAppWebViewSettings(
        allowFileAccessFromFileURLs: false,
        allowUniversalAccessFromFileURLs: false,
        mixedContentMode: MixedContentMode.MIXED_CONTENT_NEVER_ALLOW,
        // allowFileAccess: true,
      ),
    );

Widget offlineDoc() => InAppWebView(
      initialSettings: InAppWebViewSettings(javaScriptEnabled: false, allowFileAccess: true),
    );
