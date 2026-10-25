import AsyncStorage from '@react-native-async-storage/async-storage';
import { persistReducer } from 'redux-persist';
import storage from 'redux-persist/lib/storage';
import { rootReducer, sessionReducer } from './reducers';

const persistConfig = {
  key: 'root',
  storage: AsyncStorage,
  whitelist: ['auth', 'settings'],
};

export const persisted = persistReducer(persistConfig, rootReducer);
export const session = persistReducer({ key: 'session', storage }, sessionReducer);
