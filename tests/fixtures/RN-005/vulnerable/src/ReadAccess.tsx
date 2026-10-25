import RNFS from 'react-native-fs';
import { WebView } from 'react-native-webview';

export const Report = ({ file }) => (
  <WebView source={{ uri: 'file://' + file }} allowingReadAccessToURL={RNFS.DocumentDirectoryPath} />
);
