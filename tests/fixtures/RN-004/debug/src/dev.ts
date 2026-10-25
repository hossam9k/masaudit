import RNFetchBlob from 'rn-fetch-blob';

export function devDownload(url: string) {
  if (__DEV__) {
    return RNFetchBlob.config({ trusty: true }).fetch('GET', url);
  }
  return RNFetchBlob.fetch('GET', url);
}
