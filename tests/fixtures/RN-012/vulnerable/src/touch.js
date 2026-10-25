import TouchID from 'react-native-touch-id';
import { authenticateAsync as bio } from 'expo-local-authentication';
export const check = () => TouchID.authenticate('Unlock the vault').then(() => true);
export const check2 = async () => (await bio()).success;
