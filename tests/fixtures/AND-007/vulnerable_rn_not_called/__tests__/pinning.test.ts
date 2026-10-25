import { initializeSslPinning } from 'react-native-ssl-public-key-pinning';

test('pins', async () => {
  await initializeSslPinning({ 'api.bank.example': { includeSubdomains: false, publicKeyHashes: ['a', 'b'] } });
});
