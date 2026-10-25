import React from 'react';
import { WebView } from 'react-native-webview';

const baseUrl = 'https://bank.example';
const page = (key: string) => `<html><body><div data-sitekey="${key}"></div></body></html>`;

// The page is inline HTML on a web base, and every navigation is checked, so no file:// page loads.
export const Recaptcha = ({ siteKey }: { siteKey: string }) => (
  <WebView
    source={{ html: page(siteKey), baseUrl }}
    allowFileAccessFromFileURLs
    onShouldStartLoadWithRequest={(e) => e.url.startsWith('https://www.google.com/recaptcha') || e.url.startsWith(baseUrl)}
  />
);
