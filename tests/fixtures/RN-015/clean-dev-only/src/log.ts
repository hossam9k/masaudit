// console.log('this is a comment, not a call');
const banner = 'console.log("inside a string")';

export function debugLog(...args: unknown[]) {
  if (__DEV__) {
    console.log(...args);
  }
}

export function trace(msg: string) {
  __DEV__ && console.debug(msg);
}

export function verbose(msg: string) {
  if (!__DEV__) return;
  console.info(msg);
}

export function report(err: Error) {
  console.error(err);   // errors and warnings are left to the crash reporter
  console.warn(banner);
}

export const logLevel = process.env.NODE_ENV !== 'production' ? console.log('dev build') : null;
