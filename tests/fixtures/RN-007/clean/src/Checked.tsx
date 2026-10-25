import { WebView } from 'react-native-webview';

const ALLOWED_HOSTS = ['app.example.com'];

export function Checked({ route }) {
  const { url } = route.params;
  if (!ALLOWED_HOSTS.includes(new URL(url).hostname)) return null;
  return <WebView source={{ uri: url }} />;
}
