import { AppState } from 'react-native';
import { refreshBalances } from './api';

// Refresh when the app comes back to the foreground ('blur' and 'focus' are Android-only events).
AppState.addEventListener('change', (state) => {
  if (state === 'active') {
    refreshBalances();
  }
});
