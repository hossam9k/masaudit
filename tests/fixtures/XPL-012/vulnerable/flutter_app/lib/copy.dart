import 'package:flutter/services.dart';

Future<void> copyToken(String accessToken) => Clipboard.setData(ClipboardData(text: accessToken));
