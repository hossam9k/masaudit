import React from 'react';
import { TextInput } from 'react-native';

export default function Secret(props: { placeholder: string; value: string; onChangeText: (t: string) => void }) {
  return <TextInput {...props} secureTextEntry />;
}
