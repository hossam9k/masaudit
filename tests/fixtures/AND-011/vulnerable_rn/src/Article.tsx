import React from 'react';
import { WebView } from 'react-native-webview';

// Inline HTML with an https base URL is an https page, so HTTP scripts in it are mixed content.
export const Article = ({ html }: { html: string }) => (
  <WebView source={{ html, baseUrl: 'https://news.example' }} mixedContentMode="always" />
);

// A variable named `html` that holds a URL: the page is a real web page.
export const Page = ({ html }: { html: string }) => <WebView source={{ uri: html }} mixedContentMode="always" />;
