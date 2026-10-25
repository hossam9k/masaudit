import React, { useState } from 'react';
import { TextInput, View } from 'react-native';
import { Input } from 'some-ui-kit';
import Secret from './Secret';

export function Login(props: object) {
  const [password, setPassword] = useState('');
  const [visible, setVisible] = useState(false);
  return (
    <View>
      <TextInput placeholder="Password" value={password} onChangeText={setPassword} secureTextEntry={!visible} />
      <TextInput placeholder="Email" textContentType="username" />
      <TextInput {...props} placeholder="Password" />
      <Input placeholder="Password" value={password} />
      <Secret placeholder="Password" value={password} onChangeText={setPassword} />
    </View>
  );
}
