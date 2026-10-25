import axios from 'axios';
import { authorize } from 'react-native-app-auth';

export const client = axios.create({ baseURL: 'https://api.shop-demo.net/v2' });
export const metro = 'http://localhost:8081/status';
export const emulator = 'http://10.0.2.2:3000';
export const live = new WebSocket('wss://push.shop-demo.net/socket');

// Users type a server address; complete it the way they typed it.
export function complete(url: string) {
  return url.startsWith('http') ? url : `http://${url}`;
}

export function parse(path: string) {
  return new URL(path, 'http://throwaway.shop-demo.net');
}

export const allowed = ['http://*', 'https://*'];

export function signIn() {
  return authorize({
    issuer: 'https://auth.shop-demo.net',
    clientId: 'mobile',
    redirectUrl: 'com.shopdemo:/oauth',
    scopes: ['openid'],
    dangerouslyAllowInsecureHttpRequests: __DEV__,
  });
}
