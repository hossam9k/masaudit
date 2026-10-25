import React, { useState } from 'react';
import { TextInput } from 'react-native';

const ADMIN_USER = 'admin', ADMIN_PASS = 'Adm1nPass';

export function login(u: string, p: string) {
  return u === ADMIN_USER && p === ADMIN_PASS ? 'granted' : 'denied';
}

export function LoginScreen({ onDone }: { onDone: () => void }) {
  const loginValue = 'admin';
  const passwordValue = 'pass123';
  const [user, setUser] = useState('');
  const [password, setPassword] = useState('');
  const submit = () => {
    if (user === loginValue && password === passwordValue) {
      onDone();
    }
  };
  return <TextInput value={password} onChangeText={setPassword} onSubmitEditing={submit} secureTextEntry />;
}

export function unlock(pin: string) {
  return '4711' === pin;
}
