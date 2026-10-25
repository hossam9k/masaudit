import React from 'react';
import { WebView } from 'react-native-webview';

export const Statement = ({ uri }: { uri: string }) => (
  <WebView
    source={{ uri }}
    webviewDebuggingEnabled
  />
);

export const Help = () => <BankWebView source={{ uri: 'https://help.bank.example' }} webviewDebuggingEnabled={true} />;
