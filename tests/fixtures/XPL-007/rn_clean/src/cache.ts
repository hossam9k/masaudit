import CryptoJS from 'crypto-js';

export function cacheKeyFor(url: string) {
  return CryptoJS.MD5(url).toString();
}
