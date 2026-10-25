import RNFS from 'react-native-fs';
import { WebView } from 'react-native-webview';
import { MyWebView } from './MyWebView';

// <WebView allowFileAccess allowUniversalAccessFromFileURLs /> was removed.
export const A = () => <WebView source={{ uri: 'https://example.com' }} allowFileAccess={false} />;
export const B = () => <WebView source={{ uri: 'https://example.com' }} allowFileAccess={__DEV__} />;
export const C = () => <WebView source={require('./page.html')} />;
export const D = ({ file }) => (
  <WebView source={{ uri: file }} allowingReadAccessToURL={`${RNFS.DocumentDirectoryPath}/reports`} />
);
export const E = () => <MyWebView allowFileAccess />;
export const F = () => <WebView source={{ html: '<p>x</p>' }} allowUniversalAccessFromFileURLs={false} />;
export const G = () => {
  const label = 'allowFileAccess';
  return <WebView source={{ uri: 'https://example.com' }} accessibilityLabel={label} />;
};
