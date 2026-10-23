import 'dart:typed_data';

import 'package:encrypt/encrypt.dart';
import 'package:pointycastle/export.dart';

final zeroIv = IV.allZerosOfLength(16);
final textIv = IV.fromUtf8('0123456789abcdef');
final listIv = IV(Uint8List.fromList(const [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]));
final params = ParametersWithIV<KeyParameter>(KeyParameter(Uint8List(32)), Uint8List(16));
