const ReactNativeBlobUtil = require('react-native-blob-util').default;

const options = {
  fileCache: true,
  'trusty': true,
};

export function upload(url, path) {
  return ReactNativeBlobUtil.config(options).fetch('POST', url, {}, ReactNativeBlobUtil.wrap(path));
}
