import React, { useState } from 'react';
import { Text, TextInput, View } from 'react-native';
import Field from './Field';

export function Login() {
  const [password, setPassword] = useState('');
  const [p, setP] = useState('');
  return (
    <View>
      <TextInput placeholder="Password" value={password} onChangeText={setPassword} />
      <Text>PIN</Text>
      <TextInput value={p} onChangeText={setP} keyboardType="number-pad" />
      <Field placeholder="Password" value={password} onChangeText={setPassword} />
    </View>
  );
}
