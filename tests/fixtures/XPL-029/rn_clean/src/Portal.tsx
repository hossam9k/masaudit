import React from 'react';
import { WebView } from 'react-native-webview';

export function Portal({ theme }: { theme: string }) {
  return (
    <WebView
      source={{ uri: 'https://portal.demo.example' }}
      injectedJavaScript={`document.body.dataset.theme = '${theme}'; true;`}
    />
  );
}
