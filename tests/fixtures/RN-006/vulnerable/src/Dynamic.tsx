import { useMemo } from 'react';
import { WebView } from 'react-native-webview';

const ANY = ['*'];

export function Browser({ url }) {
  return <WebView source={{ uri: url }} originWhitelist={ANY} />;
}

export function Checkout({ checkoutUrl }) {
  const origins = useMemo(() => ['*'], []);
  return <WebView source={{ uri: checkoutUrl }} originWhitelist={origins} />;
}
