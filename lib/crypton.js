var _ = require('lodash');
var Configuration = require('./configuration');
var cryptoManager = require('./cryptoManager');

function Crypton(options) {
  if (!_.isNull(options) && !_.isUndefined(options)) {
    Configuration.init(options);
  }
}

Crypton.prototype.init = function(options) {
  Configuration.init(options);
}

Crypton.prototype.getConfig = function() {
  return Configuration.getParams();
}

//Expose crypton public functions
Crypton.prototype.cipher = cryptoManager.cipher;
Crypton.prototype.decipher = cryptoManager.decipher;
Crypton.prototype.compare = cryptoManager.compare;
Crypton.prototype.crypt = cryptoManager.crypt;
Crypton.prototype.verify = cryptoManager.verify;

exports = module.exports = function(options) {
  return new Crypton(options);
}
