export function mustUpdate(config: { minAppVersion: string }, current: string) {
  return current < config.minAppVersion;
}
