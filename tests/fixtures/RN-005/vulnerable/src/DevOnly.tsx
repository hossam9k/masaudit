import { WebView } from 'react-native-webview';

// Reported, but lowered: only debug builds render this screen.
export const Inspector = ({ page }) => (
  <>{__DEV__ && <WebView source={{ uri: page }} allowUniversalAccessFromFileURLs />}</>
);
