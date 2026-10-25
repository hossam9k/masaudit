import AsyncStorage from '@react-native-async-storage/async-storage';
import { persistReducer } from 'redux-persist';
import createSensitiveStorage from 'redux-persist-sensitive-storage';
import { encryptTransform } from 'redux-persist-transform-encrypt';
import { authReducer, rootReducer, settingsReducer } from './reducers';

const sensitiveStorage = createSensitiveStorage({ keychainService: 'app' });

export const settings = persistReducer(
  { key: 'root', storage: AsyncStorage, whitelist: ['settings', 'theme'] },
  settingsReducer,
);
export const auth = persistReducer({ key: 'auth', storage: sensitiveStorage }, authReducer);
export const root = persistReducer(
  {
    key: 'root',
    storage: AsyncStorage,
    whitelist: ['auth'],
    transforms: [encryptTransform({ secretKey: process.env.KEY ?? '' })],
  },
  rootReducer,
);
