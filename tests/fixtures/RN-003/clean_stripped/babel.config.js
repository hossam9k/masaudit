module.exports = function (api) {
  api.cache(true);
  const isProd = process.env.NODE_ENV === 'production';
  return {
    presets: ['module:@react-native/babel-preset'],
    plugins: isProd ? [['transform-remove-console', { exclude: ['error'] }]] : [],
  };
};
