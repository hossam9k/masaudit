import React from 'react';
import { WebView } from 'react-native-webview';

export function Help() {
  return <WebView source={{ uri: 'https://help.example.com' }} allowUniversalAccessFromFileURLs />;
}
