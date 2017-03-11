var _ = require('lodash');
var Promise = require('bluebird');
var crypto = require('crypto');
var bcrypt = require('bcrypt');
var appconfig = require('./configuration').getParams();
var EncryptCryptonError = require('./exceptions/encryptCryptonError');
var CipherCryptonError = require('./exceptions/cipherCryptonError');
var DecipherCryptonError = require('./exceptions/decipherCryptonError');
var CompareCryptonError = require('./exceptions/compareCryptonError');
var VerifyCryptonError = require('./exceptions/verifyCryptonError');
var RandomBytesCryptonError = require('./exceptions/randomBytesCryptonError');

/**
* Cipher a text with crypto. The operation is reversible
* @param {string} text
* @param {object} [options]
* @return {Promise<string>}
* @throws CipherCryptonError
*/
var cipherText = function(text, options) {
  return new Promise(function(resolve, reject) {
    try {
      var settings = getCryptoOverrideOptions(options);
      var cipher = crypto.createCipher(settings.algorithm, settings.secretKey);
      var crypted = cipher.update(text, settings.inputEncoding, settings.outputEncoding);
      crypted += cipher.final(settings.outputEncoding);

      return resolve(crypted);
    }
    catch (err) {
      return reject(new CipherCryptonError(err));
    }
  });
}

/**
* Decipher a ciphered text with crypto
* @param {string} text
* @param {options} [options]
* @return {Promise<string>}
* @throws DecipherCryptonError
*/
var decipherText = function(text, options) {
  return new Promise(function(resolve, reject) {
    try {
      var settings = getCryptoOverrideOptions(options);
      var decipher = crypto.createDecipher(settings.algorithm, settings.secretKey);
      var decrypted = decipher.update(text, settings.outputEncoding, settings.inputEncoding);
      decrypted += decipher.final(settings.inputEncoding);

      return resolve(decrypted);
    }
    catch (err) {
      return reject(new DecipherCryptonError(err));
    }
  });
}

/**
* Check if the clear text matches with the ciphered text. If force is specified
* it accepts two ciphered strings to compare
* @param {string} text
* @param {string} ciphered
* @param {bool} force
* @param {options} [options]
* @return {Promise<bool>}
* @throws CompareCryptonError
*/
var compareText = function(text, cipher, force, options) {
  return new Promise(function(resolve, reject) {
    var promise = Promise.resolve(text);
    if (force === true) {
      promise = decipherText(text, options)
      .then(function(dec) {
        return dec;
      })
      .catch(function(err) {
        return text;
      });
    }

    return promise.
    then(function(text) {
      return cipherText(text, options);
    })
    .then(function(hash) {
      if (hash === cipher) {
        return resolve(true);
      }
      return resolve(false);
    })
    .catch(function(err) {
      return reject(new CompareCryptonError(err));
    });
  });
}

/**
* Crypt a text with bcrypt. The operation is not reversible
* @param {string} text
* @param {object} [options]
* @return {Promise<string>}
* @throws EncryptCryptonError
*/
var cryptText = function(text, options) {
  var settings = getBcryptOverrideOptions(options);

  return bcrypt.genSalt(settings.saltRounds)
  .then(function (salt) {
    return bcrypt.hash(text, salt, null);
  })
  .then(function (hash) {
    return hash;
  })
  .catch(function(err) {
    throw new EncryptCryptonError(err);
  });
}

/**
* Check if the clear text matches with the crypted text
* @param {string} text
* @param {string} crypted
* @return {Promise<bool>}
* @throws VerifyCryptonError
*/
var verifyText = function(text, crypted) {
  return bcrypt.compare(text, crypted)
  .catch(function(err) {
    throw new VerifyCryptonError(err);
  });
}

var getCryptoOverrideOptions = function(options) {
  if (_.isNull(options) || _.isUndefined(options)) {
    return appconfig.crypto;
  }
  var settings = {
    secretKey: selectConfigValue(options['secretKey'], appconfig.crypto['secretKey']),
    algorithm: selectConfigValue(options['algorithm'], appconfig.crypto['algorithm']),
    inputEncoding: selectConfigValue(options['inputEncoding'], appconfig.crypto['inputEncoding']),
    outputEncoding: selectConfigValue(options['outputEncoding'], appconfig.crypto['outputEncoding'])
  };
  return settings;
}

/**
* Get random bytes of a given length
* @param {int} length
* @param {string} [outputEncoding]
* @return {Promise<string>}
* @throws RandomBytesCryptonError
*/
var randomBytes = function(len, outputEncoding) {
  return new Promise(function(resolve, reject) {
    var out = selectConfigValue(outputEncoding, 'hex');

    try {
      crypto.randomBytes(len, function(err, buf) {
        if (err) {
          return reject(new RandomBytesCryptonError(err));
        }
        return resolve(buf.toString(out));
      });
    }
    catch (err) {
      return reject(new RandomBytesCryptonError(err));
    }
  });
}

var getBcryptOverrideOptions = function(options) {
  if (_.isNull(options) || _.isUndefined(options)) {
    return appconfig.bcrypt;
  }
  var settings = {
    saltRounds: selectConfigValue(options['saltRounds'], appconfig.bcrypt['saltRounds'])
  };
  return settings;
}

var selectConfigValue = function(custom, def) {
  if (_.isNull(custom) || _.isUndefined(custom) || (_.isArray(custom) && custom.length <= 0)) {
    return def;
  }
  return custom;
}

/* Public methods */
module.exports.cipher = cipherText;
module.exports.decipher = decipherText;
module.exports.compare = compareText;
module.exports.crypt = cryptText;
module.exports.verify = verifyText;
module.exports.randomBytes = randomBytes;
