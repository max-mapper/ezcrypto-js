(function() {
  var ezcrypto = this.ezcrypto = {};
  
  ezcrypto.generateKeys = function() {
    var keys = RSAGenerate(ezcrypto.randomNumber());
    return {'public': keys.n, 'private': keys.d};
  }
  
  ezcrypto.encrypt = function(message, publicKey) {
    var bigNumSessionKey = new BigInteger(128, 1, ezcrypto.randomNumber());
    var sessionKey = bigNumSessionKey.toString(16);
    var encryptedMessage = byteArrayToHex(rijndaelEncrypt(message, hexToByteArray(sessionKey), 'ECB'));
    var encryptedKey = RSAEncrypt(sessionKey, publicKey);
    return {'key': encryptedKey, 'message': encryptedMessage};
  }
  
  ezcrypto.decrypt = function(encryptedMessage, encryptedKey, publicKey, privateKey) {
    var decryptedKey = RSADecrypt(encryptedKey, publicKey, privateKey);
    var decryptedMessage = byteArrayToString(rijndaelDecrypt(hexToByteArray(encryptedMessage), hexToByteArray(decryptedKey), 'ECB'));
    return decryptedMessage;
  }
  
  ezcrypto.randomNumber = function() {
    return new SecureRandom();
  }
  
  function load(scripts) {
    for (var i=0; i < scripts.length; i++) {
      document.write('<script src="'+scripts[i]+'"><\/script>')
    };
  };

  load([
    "vendor/pidcrypt.js",
    "vendor/pidcrypt_util.js",
    "vendor/asn1.js",
    "vendor/jsbn.js",
    "vendor/rng.js",
    "vendor/prng4.js",
    "vendor/rsa.js",
    "vendor/genkey.js",
    "vendor/rijndael.js",
    "vendor/custom.js"
  ]);
  
})();