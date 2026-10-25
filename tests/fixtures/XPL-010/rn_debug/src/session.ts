export function trace(accessToken: string) {
  if (__DEV__) {
    console.log('token', accessToken);
  }
}
