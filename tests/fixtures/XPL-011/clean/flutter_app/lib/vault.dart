import 'package:encrypt/encrypt.dart';
import 'package:flutter/widgets.dart';

final key = Key.fromSecureRandom(32);
const field = Key('password_field');
final other = ValueKey('token');
