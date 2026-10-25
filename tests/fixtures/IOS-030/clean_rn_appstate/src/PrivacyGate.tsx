import React, { useEffect, useState } from 'react';
import { AppState, View } from 'react-native';
import { BlurView } from '@react-native-community/blur';

export function PrivacyGate({ children }: { children: React.ReactNode }) {
  const [hidden, setHidden] = useState(false);
  useEffect(() => {
    const sub = AppState.addEventListener('change', (state) => setHidden(state !== 'active'));
    return () => sub.remove();
  }, []);
  return <View style={{ flex: 1 }}>{children}{hidden && <BlurView style={{ position: 'absolute' }} />}</View>;
}
