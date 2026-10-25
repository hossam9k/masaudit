import React from 'react';
import { WebView } from 'react-native-webview';

export function Body({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

export function Page({ title, body }: { title: string; body: string }) {
  return <WebView originWhitelist={['*']} source={{ html: `<h1>${title}</h1><div>${body}</div>` }} />;
}
