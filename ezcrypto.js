
if (typeof(document) === 'undefined'){
  nodemode = true;
  document = {}
  document.write = function(foo){};
  var SecureRandom = require('./vendor/rng.js').SecureRandom;
  var RSAGenerate = require('./vendor/unhosted_encryption.js').RSAGenerate;
  //var unhosted = require('./vendor/unhosted.js');
  var RSASign = require('./vendor/unhosted.js').unhosted.RSASign;
  var Verify = require('./vendor/unhosted.js').unhosted.checkPubSign;
  //console.log(RSASign);
  var sha1 = require('./vendor/sha1.js');
  //console.log(sha1.sha1.hex);
}

(function() {
  var ezcrypto = this.ezcrypto = {};
  
  // Basic/simple API
  ezcrypto.generateKey = function(password) {
    var RSAkeys = RSAGenerate(ezcrypto.randomNumber());
    var key = {'public': RSAkeys.n, 'private': RSAkeys.d};
    if (password) {
      key['encryptedPassword'] = ezcrypto.encryptRSA(password, key.public);
    }
    return key;
  }
  
  ezcrypto.sign = function(hexHash, n, d) { return RSASign(hexHash, n, d).toString(16) };
  ezcrypto.verify = function(msg, sig, pubkey){ return Verify(msg, sig, pubkey) };
    
  ezcrypto.encrypt = function(message, key) {
    var password = ezcrypto.getPassword(key);
    return ezcrypto.encryptAES(message, password)
  }
  
  ezcrypto.decrypt = function(message, key) {
    var password = ezcrypto.getPassword(key);
    return ezcrypto.decryptAES(message, password);
  }
  
  // Core encryption functions
  ezcrypto.encryptRSA = function(message, publicKey) {
    return RSAEncrypt(message, publicKey);
  }
  
  ezcrypto.decryptRSA = function(message, publicKey, privateKey) {
    return RSADecrypt(message, publicKey, privateKey);
  }
  
  ezcrypto.encryptAES = function(message, password){
    var aes = new pidCrypt.AES.CBC();
    var encryptedMessage = aes.encryptText(message, password, {nBits: 128});
    return encryptedMessage;
  }
  
  ezcrypto.decryptAES = function(message, password){
    var aes = new pidCrypt.AES.CBC();
    var plain = aes.decryptText(message, password, {nBits: 128});
    return plain;
  }
  
  // Utility functions
  ezcrypto.getPassword = function(key) {
    var password = key.public;
    if ("encryptedPassword" in key) password = ezcrypto.decryptRSA(key['encryptedPassword'], key.public, key.private);
    return password;
  }
  
  ezcrypto.hash = function(data){ return sha1.sha1.hex(data); } //console.log(sha1.sha1.hex());
  
  ezcrypto.randomNumber = function() {
    return new SecureRandom();
  }
  
  ezcrypto.loadScripts = function(scripts) {
    for (var i=0; i < scripts.length; i++) {
      document.write('<script src="'+scripts[i]+'"><\/script>')
    };
  };
  
  ezcrypto.scripts = [
    "vendor/pidcrypt.js",
    "vendor/pidcrypt_util.js",
    "vendor/jsbn.js",
    "vendor/md5.js",
    "vendor/aes_core.js",
    "vendor/aes_cbc.js",
    "vendor/rng.js",
    "vendor/prng4.js",
    "vendor/rsa.js",
    "vendor/unhosted_encryption.js"
  ]

  ezcrypto.loadScripts(ezcrypto.scripts);
  
})();


//console.log(ezcrypto.scripts);
if (nodemode){
  for (x in ezcrypto.scripts){
    var script = ezcrypto.scripts[x];
    //console.log(script);
    //require("./"+script);
  }
  
  exports.ezcrypto= ezcrypto;
}

