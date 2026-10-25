import { authorize } from 'react-native-app-auth';
import { AuthRequest, ResponseType } from 'expo-auth-session';

export function signIn() {
  return authorize({ issuer: 'https://id.demo.example', clientId: 'app', redirectUrl: 'demo:/cb', scopes: [], usePKCE: false });
}

export const implicit = new AuthRequest({ clientId: 'app', redirectUri: 'demo:/cb', responseType: ResponseType.Token });
