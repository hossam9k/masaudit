module.exports = ({ config }) => ({
  ...config,
  name: 'Bank',
  slug: 'bank',
  android: {
    package: process.env.APP_ID ?? 'com.bank.app',
  },
});
