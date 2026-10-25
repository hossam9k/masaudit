import { fetch as pinnedFetch } from 'react-native-ssl-pinning';
import RNFetchBlob from 'rn-fetch-blob';

export function getProfile(url: string) {
  return pinnedFetch(url, {
    method: 'GET',
    disableAllSecurity: false,
    sslPinning: { certs: ['api_example_com'] },
  });
}

export function download(url: string, ignoreTlsErrors: boolean) {
  // trusty: true was used during development
  RNFetchBlob.config({ trusty: __DEV__ }).fetch('GET', url);
  return RNFetchBlob.config({ trusty: ignoreTlsErrors }).fetch('GET', url);
}
