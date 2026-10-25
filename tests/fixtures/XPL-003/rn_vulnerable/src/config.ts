import jwt from 'jsonwebtoken';

export const API_SECRET = 'q8Zr2Lt6Vx1Nc4Bm7Ka9';

export const oauth = {
  clientId: 'mobile-app',
  clientSecret: "Zq8Lr2Vt6Yx1Nc4B",
};

export const PREMIUM_API_KEY: string = 'sk_demo_9f8a2c1b4e7d';

export function signSession(userId: string) {
  return jwt.sign({ sub: userId }, 'h7Kd92LmQpX3', { expiresIn: '1h' });
}

export const REPORTS_URL = 'https://reporter:Xy7Kq2Lm@reports.demo.example/v1';

export const basicAuth = `Basic ${btoa('mobile:Qx7v2Lp9')}`;
