import React, { useState } from 'react';
import { Button, TextInput } from 'react-native';
import { WebView } from 'react-native-webview';

export const Browser = () => {
  const [path, setPath] = useState('https://example.com/');
  const [uriPath, setUriPath] = useState('https://example.com/');
  return (
    <>
      <TextInput value={path} onChangeText={setPath} />
      <Button title="Go" onPress={() => setUriPath(path)} />
      <WebView source={{ uri: uriPath }} />
    </>
  );
};
