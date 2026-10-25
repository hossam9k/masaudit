import React from 'react';
import { WebView } from 'react-native-webview';
import ExtendedWebView from './ExtendedWebView';

// Inline HTML with no base URL loads as about:blank, not an https page: nothing can be mixed.
export const Video = ({ html }: { html: string }) => (
  <WebView source={{ html }} mixedContentMode="always" />
);

// A wrapper that takes the page as `html`.
export const Note = ({ html }: { html: string }) => <ExtendedWebView html={html} mixedContentMode="always" />;
