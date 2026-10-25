const AES = require('crypto-js/aes');
module.exports = (data) => AES.encrypt(data, 'hunter2').toString();
