import { initializeSslPinning } from 'react-native-ssl-public-key-pinning';
import { PIN_CONFIG } from './config';

// The config comes from another module: its pin count isn't read here.
export const setUpPinning = () => initializeSslPinning(PIN_CONFIG);
