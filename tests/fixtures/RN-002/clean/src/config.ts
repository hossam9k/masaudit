import Config from 'react-native-config';

// Config.STRIPE_SECRET_KEY moved to the backend.
export const apiUrl = Config.API_URL;
export const mapsKey = Config.GOOGLE_MAPS_API_KEY;
export const dsn = process.env.EXPO_PUBLIC_SENTRY_DSN;
export const anon = process.env.EXPO_PUBLIC_SUPABASE_ANON_KEY;
export const publishable = process.env.EXPO_PUBLIC_STRIPE_PUBLISHABLE_KEY;
const { EXPO_PUBLIC_API_SECRET } = process.env;
export const label = 'Config.API_SECRET';
export { EXPO_PUBLIC_API_SECRET };
