export default ({ config }) => ({
  ...config,
  extra: {
    apiUrl: 'https://api.example.com',
    stripeSecretKey: '{{FAKE_STRIPE_LIVE}}',
  },
});
