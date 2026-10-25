import RNFetchBlob from 'rn-fetch-blob';

export function download(url: string) {
  return RNFetchBlob.config({ fileCache: true, trusty: true }).fetch('GET', url);
}
