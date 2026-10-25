// A build script in the app package's own tools folder: it runs on the developer's machine, not in the app.
const fs = require('fs');
console.log('Encoding assets...');
fs.writeFileSync('assets.json', '{}');
console.info('Done.');
