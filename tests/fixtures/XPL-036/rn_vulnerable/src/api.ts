export const API = 'http://192.168.1.20:3000/api';
export const EMULATOR = 'http://10.0.2.2:8080';

export function dump() {
  return fetch('https://api.shop-demo.net/api/debug/state');
}
