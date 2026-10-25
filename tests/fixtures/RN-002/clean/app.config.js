export default ({ config }) => ({
  ...config,
  extra: {
    eas: { projectId: '0f3c8a52-1b6e-4d2f-9a7c-5e8b1d4c2a90' },
    apiSecret: process.env.API_SECRET,
    sentryAuthToken: `${process.env.SENTRY_AUTH_TOKEN}`,
  },
});
