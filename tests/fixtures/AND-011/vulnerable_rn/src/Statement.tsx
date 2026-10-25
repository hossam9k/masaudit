import React from 'react';
import { WebView as Web } from 'react-native-webview';

export const Statement = ({ uri }: { uri: string }) => (
  <Web source={{ uri }} mixedContentMode="always" />
);

export const Help = () => <Web source={{ uri: 'https://help.bank.example' }} mixedContentMode={'compatibility'} />;
