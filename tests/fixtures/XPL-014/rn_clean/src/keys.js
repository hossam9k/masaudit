import forge from 'node-forge';

export function makeKeys() {
  return forge.pki.rsa.generateKeyPair({ bits: 3072, e: 0x10001 });
}
