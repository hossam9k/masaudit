export function makeSessionToken() {
  return Math.random().toString(36).slice(2);
}

export const otp = Math.floor(Math.random() * 1000000).toString();
