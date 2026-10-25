import JWT from 'expo-jwt';

// A storage key named like a secret comes first in the file; the JWT secret below must still be found.
const storageKey = '@myapp/session-storage-v2';

export const sign = (claims: object) => JWT.encode(claims, 'Zq8xHw2LmP4vRt9K', { algorithm: 'HS256' });
export { storageKey };
