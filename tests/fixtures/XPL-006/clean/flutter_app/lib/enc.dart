import 'dart:typed_data';

import 'package:encrypt/encrypt.dart';

// final textIv = IV.fromUtf8('0123456789abcdef');
final randomIv = IV.fromSecureRandom(12);
final lengthIv = IV.fromLength(12);
IV restore(String stored) => IV.fromBase64(stored);
IV wrap(Uint8List bytes) => IV(bytes);
