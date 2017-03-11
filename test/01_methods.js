var cheerio = require('cheerio')
var chai = require('chai');
var should = chai.should();
var expect = chai.expect;
var Crypton = require('../')();
var Promise = require('bluebird');

var text = 'example';
var ciphered = null;
var crypted = null;
var options = {
  crypto: {
    secretKey: 'o!rDE(Qbrq7u4OV',
    algorithm: 'AES-256-CBC',
    inputEncoding: 'utf8',
    outputEncoding: 'base64'
  },
  bcrypt: {
    saltRounds: 5
  }
};

Crypton.init(options);

// Cipher method
describe('Call Crypton cipher method', function() {
  it('should return a ciphered text', function() {
    return Crypton.cipher(text)
    .then(function(res) {
      ciphered = res;
      expect(res).to.exist;
    });
  });
  it('should return a CipherCryptonError exception', function() {
    return Crypton.cipher(null)
    .catch(function(err) {
      expect(err.name).to.be.equal('CipherCryptonError');
    });
  });
});

// Decipher method
describe('Call Crypton decipher method', function() {
  it('should return a deciphered text', function() {
    return Crypton.decipher(ciphered)
    .then(function(res) {
      expect(res).to.be.equal(text);
    });
  });
  it('should return a DecipherCryptonError exception', function() {
    return Crypton.decipher(null)
    .catch(function(err) {
      expect(err.name).to.be.equal('DecipherCryptonError');
    });
  });
});

// Compare method
describe('Call Crypton compare method', function() {
  it('should return a true value', function() {
    return Crypton.compare(text, ciphered)
    .then(function(res) {
      expect(res).to.be.equal(true);
    });
  });
  it('should return a false value', function() {
    return Crypton.compare('fake', ciphered)
    .then(function(res) {
      expect(res).to.be.equal(false);
    });
  });
  it('should return a CompareCryptonError exception', function() {
    return Crypton.compare(null, ciphered)
    .catch(function(err) {
      expect(err.name).to.be.equal('CompareCryptonError');
    });
  });
});

// Crypt method
describe('Call Crypton encrypt method', function() {
  it('should return a crypted text', function() {
    return Crypton.crypt(text)
    .then(function(res) {
      crypted = res;
      expect(res).to.exist;
    });
  });
  it('should return a EncryptCryptonError exception', function() {
    return Crypton.crypt(null)
    .catch(function(err) {
      expect(err.name).to.be.equal('EncryptCryptonError');
    });
  });
});

// Verify method
describe('Call Crypton verify method', function() {
  it('should return a true value', function() {
    return Crypton.verify(text, crypted)
    .then(function(res) {
      expect(res).to.be.equal(true);
    });
  });
  it('should return a false value', function() {
    return Crypton.verify('fake', crypted)
    .then(function(res) {
      expect(res).to.be.equal(false);
    });
  });
  it('should return a VerifyCryptonError exception', function() {
    return Crypton.verify(null, ciphered)
    .catch(function(err) {
      expect(err.name).to.be.equal('VerifyCryptonError');
    });
  });
});
