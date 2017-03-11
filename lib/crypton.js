var _ = require('lodash');
var Configuration = require('./configuration');
var cryptoManager = require('./cryptoManager');

function Crypton(options) {
  if (!_.isNull(options) && !_.isUndefined(options)) {
    Configuration.init(options);
  }
}

//Expose crypton public functions
Crypton.prototype.getConfig = function() {
  return Configuration.getParams();
}
Crypton.prototype.init = function(options) {
  return Configuration.init(options);
}
Crypton.prototype.cipher = cryptoManager.cipher;
Crypton.prototype.decipher = cryptoManager.decipher;
Crypton.prototype.compare = cryptoManager.compare;
Crypton.prototype.crypt = cryptoManager.crypt;
Crypton.prototype.verify = cryptoManager.verify;
Crypton.prototype.randomBytes = cryptoManager.randomBytes;

exports = module.exports = Crypton;
