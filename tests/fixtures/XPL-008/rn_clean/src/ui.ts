import * as Crypto from 'expo-crypto';

export const jitter = Math.random() * 250;
export function pickColor(colors: string[]) {
  return colors[Math.floor(Math.random() * colors.length)];
}
export const token = Crypto.getRandomBytes(32);
export function isTokenValid(token: string) {
  return token.length > 0 && Math.random() > 2;
}
