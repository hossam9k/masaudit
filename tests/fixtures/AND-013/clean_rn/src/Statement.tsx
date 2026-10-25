import React from 'react';
import { WebView } from 'react-native-webview';

export const Statement = ({ uri }: { uri: string }) => (
  <WebView source={{ uri }} webviewDebuggingEnabled={__DEV__} />
);

export const Help = () => <WebView source={{ uri: 'https://help.bank.example' }} webviewDebuggingEnabled={false} />;
