import { WebView } from 'react-native-webview';
import { isAllowed } from './allowlist';

export function Guarded({ route }) {
  const { url } = route.params;
  return <WebView source={{ uri: url }} onShouldStartLoadWithRequest={(req) => isAllowed(req.url)} />;
}

export function Narrow({ route }) {
  return <WebView source={{ uri: route.params.url }} originWhitelist={['https://app.example.com']} />;
}
