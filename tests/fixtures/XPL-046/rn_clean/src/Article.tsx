import React from 'react';
import DOMPurify from 'dompurify';
import { WebView } from 'react-native-webview';

export function Body({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
}

export function Static() {
  return <div dangerouslySetInnerHTML={{ __html: '<b>Terms</b>' }} />;
}

export function Page() {
  return <WebView source={{ html: '<h1>Help</h1>' }} />;
}
