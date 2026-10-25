// TODO: call initializeSslPinning({ ... }) before the first request.
import { isSslPinningAvailable } from 'react-native-ssl-public-key-pinning';

export const pinningReady = isSslPinningAvailable();
export const apiBase = 'https://api.bank.example';
