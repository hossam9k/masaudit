import React from 'react';
import { WebView } from 'react-native-webview';

const ALLOWED = ['https:'];

// A browser screen: every URL goes through the app's own scheme check.
export const Browser = ({ url }: { url: string }) => (
  <WebView
    source={{ uri: url }}
    originWhitelist={['*']}
    onShouldStartLoadWithRequest={(e) => ALLOWED.some((p) => e.url.startsWith(p))}
  />
);
