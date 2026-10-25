import { WebView } from 'react-native-webview';

export const Terms = ({ url }: { url: string }) => (
  <WebView source={{ uri: url }} allowFileAccess={true} />
);
