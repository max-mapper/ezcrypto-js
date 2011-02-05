var ezcrypto = require('./ezcrypto.js').ezcrypto;
var foo = ezcrypto.generateKey();
var hash = ezcrypto.hash("i like cheese");
var signature = ezcrypto.sign(hash, foo.public, foo.private);
var test = ezcrypto.verify("i like cheese", signature, foo.public)
console.log(signature);
console.log(hash);
console.log(foo);
console.log(test);
