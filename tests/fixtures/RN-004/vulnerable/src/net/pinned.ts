import { fetch as pinnedFetch } from 'react-native-ssl-pinning';

export function getProfile(url: string) {
  return pinnedFetch(url, {
    method: 'GET',
    disableAllSecurity: true,
    headers: { Accept: 'application/json' },
  });
}
