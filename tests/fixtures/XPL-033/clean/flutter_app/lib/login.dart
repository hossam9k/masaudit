import 'package:flutter/material.dart';

Widget passwordField(bool hidden) => TextField(obscureText: hidden, decoration: const InputDecoration(labelText: 'Password'));
Widget emailField() => const TextField(decoration: InputDecoration(labelText: 'Email'));
