import React from 'react';
import WebView from 'react-native-webview';

// mixedContentMode="always" would load HTTP scripts inside HTTPS pages.
export const Statement = ({ uri }: { uri: string }) => (
  <WebView source={{ uri }} mixedContentMode="never" />
);

export const label = 'mixedContentMode="always"';
