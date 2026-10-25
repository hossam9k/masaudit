const shared = require('./config/shared');

export default ({ config }) => ({
  ...config,
  ...shared.updatesFor(process.env.APP_ENV),
});
