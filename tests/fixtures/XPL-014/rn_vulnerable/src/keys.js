import forge from 'node-forge';

export function makeKeys() {
  return forge.pki.rsa.generateKeyPair({ bits: 1024, e: 0x10001 });
}
