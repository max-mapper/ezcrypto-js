var ezcrypto = require('./ezcrypto.js').ezcrypto;
var keys = ezcrypto.generateKey();

// sign/verify
var hash = ezcrypto.hash("i like cheese");
var signature = ezcrypto.sign(hash, keys.public, keys.private);
var verifyTest = ezcrypto.verify("i like cheese", signature, keys.public)
console.log("{'test': 'sign/verify', 'passed': '" + verifyTest +"'}");

// randomly generated key; stronger encryption
var key = ezcrypto.generateKey();
var encryptedData = ezcrypto.encrypt('potato', key);
var rsaTest = ezcrypto.decrypt(encryptedData, key);
console.log("{'test': 'rsa crypto', 'passed': '" + rsaTest +"'}");

// with a password; weaker encryption
var key = ezcrypto.generateKey('password');
var encryptedData = ezcrypto.encrypt('nachos', key);
var rsaPasswordTest = ezcrypto.decrypt(encryptedData, key);
console.log("{'test': 'rsa crypto + password', 'passed': '" + rsaPasswordTest +"'}");


