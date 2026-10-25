import { initializeSslPinning } from 'react-native-ssl-public-key-pinning';

export async function setUpPinning(): Promise<void> {
  await initializeSslPinning({
    'api.bank.example': {
      includeSubdomains: true,
      publicKeyHashes: ['CLOmM1/OXvSPjw5UOYbAf9GKOxImEp9hhku9W90fHMk='],
    },
  });
}
