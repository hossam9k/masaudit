import React from 'react';
import { WebView } from 'react-native-webview';

// Bundled HTML loads as a file:// page, so the switch applies even with a navigation check.
export const Terms = () => (
  <WebView
    source={require('./terms.html')}
    allowFileAccessFromFileURLs
    onShouldStartLoadWithRequest={(e) => e.url.startsWith('https://bank.example')}
  />
);
