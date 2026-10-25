const ENVIRONMENTS = {
  staging: 'https://staging.shop-demo.net',
  production: 'https://api.shop-demo.net',
};

export const API = __DEV__ ? 'http://192.168.1.20:3000' : ENVIRONMENTS.production;
export const hint = { placeholder: 'https://10.20.30.40:3000' };
export const routes = { Debug: '/sys/debug' };
