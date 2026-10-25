import { fetch } from 'react-native-ssl-pinning';

export function getBalance(token) {
  return fetch('https://api.bank.example/balance', {
    method: 'GET',
    headers: { Authorization: `Bearer ${token}` },
    sslPinning: { certs: ['api_primary', 'api_backup'] },
  });
}
