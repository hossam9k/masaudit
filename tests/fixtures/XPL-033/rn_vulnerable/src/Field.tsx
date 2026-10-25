import React from 'react';
import { TextInput } from 'react-native';

const Field = (props: { placeholder: string; value: string; onChangeText: (t: string) => void }) => (
  <TextInput placeholder={props.placeholder} value={props.value} onChangeText={props.onChangeText} />
);

export default Field;
