import 'package:flutter_inappwebview/flutter_inappwebview.dart';

Widget helpPage() => InAppWebView(
      initialSettings: InAppWebViewSettings(
        allowFileAccessFromFileURLs: true,
        allowUniversalAccessFromFileURLs: true,
        mixedContentMode: MixedContentMode.MIXED_CONTENT_ALWAYS_ALLOW,
        allowFileAccess: true,
      ),
    );

final legacy = InAppWebViewGroupOptions(
  android: AndroidInAppWebViewOptions(mixedContentMode: AndroidMixedContentMode.MIXED_CONTENT_ALWAYS_ALLOW),
);
