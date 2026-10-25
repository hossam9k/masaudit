const { withAndroidManifest } = require('expo/config-plugins');

// Points the generated manifest at rules that exclude the token cache from backups.
module.exports = (config) =>
  withAndroidManifest(config, (cfg) => {
    const app = cfg.modResults.manifest.application[0];
    app.$['android:dataExtractionRules'] = '@xml/data_extraction_rules';
    app.$['android:fullBackupContent'] = '@xml/backup_rules';
    return cfg;
  });
