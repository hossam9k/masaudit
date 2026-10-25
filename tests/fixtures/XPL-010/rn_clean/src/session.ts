export function report(user: { accessToken?: string }, password: string) {
  console.log('token present:', !!user.accessToken);
  console.log('password length', password.length);
  console.warn('Token refresh failed');
  logger.info('token', user.accessToken);
}

declare const logger: { info: (...a: unknown[]) => void };
