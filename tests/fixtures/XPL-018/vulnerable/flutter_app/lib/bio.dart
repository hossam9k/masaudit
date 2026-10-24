import 'package:local_auth/local_auth.dart';

Future<bool> confirm(LocalAuthentication auth) => auth.authenticate(localizedReason: 'Confirm transfer');
