import Config from 'react-native-config';
import jwt from 'jsonwebtoken';

export const labels = {
  clientSecret: 'Client secret',
  password: 'Password',
};

export const PASSWORD_KEY = 'user_password_key_v2';
export const E2E_PRIVATE_KEY = 'RC_E2E_PRIVATE_KEY';
export const apiKey = Config.API_KEY;
export const clientSecret: string = Config.CLIENT_SECRET ?? '';

export function check(token: string, publicKey: string) {
  return jwt.verify(token, publicKey);
}

export const DOCS_URL = 'https://user:password@host.example/path';
export const accessToken = 'e2e-access-token-for-ui-tests';
