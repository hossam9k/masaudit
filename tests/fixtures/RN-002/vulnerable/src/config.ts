import Config from 'react-native-config';

export const stripeKey = Config.STRIPE_SECRET_KEY;
const { API_SECRET, API_URL } = Config;

export { API_SECRET, API_URL };
