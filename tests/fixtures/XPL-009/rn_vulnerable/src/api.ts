import axios from 'axios';
import { authorize } from 'react-native-app-auth';

export const client = axios.create({ baseURL: 'http://api.shop-demo.net/v2' });

export function profile(id: string) {
  return fetch(`http://api.shop-demo.net/users/${id}`);
}

export const live = new WebSocket('ws://push.shop-demo.net/socket');

export function imageUrl(host: string, name: string) {
  return 'http://' + host + '/img/' + name;
}

export function signIn() {
  return authorize({
    issuer: 'https://auth.shop-demo.net',
    clientId: 'mobile',
    redirectUrl: 'com.shopdemo:/oauth',
    scopes: ['openid'],
    dangerouslyAllowInsecureHttpRequests: true,
  });
}
