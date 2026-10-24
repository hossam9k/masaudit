import 'dart:convert';
import 'package:pointycastle/export.dart';

final params = Pbkdf2Parameters(utf8.encode('fixed-salt'), 600000, 32);
