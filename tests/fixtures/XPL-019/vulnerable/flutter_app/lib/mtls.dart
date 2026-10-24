import 'dart:io';

void configure(SecurityContext ctx, List<int> bytes) {
  ctx.usePrivateKeyBytes(bytes, password: 'client-pass');
}
