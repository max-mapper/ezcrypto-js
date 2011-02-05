if (typeof(document) === 'undefined' || typeof(nodemode) !== "undefined"){
  nodemode = true;
  document = {};
  document.write = function(foo){};
  var BigInteger   = require('./jsbn.js').BigInteger;
  var SecureRandom = require('./rng.js').SecureRandom;
}

var unhosted = this.unhosted = {};

// Generate a new random private key B bits long, using public expt E
unhosted.RSAGenerate = function(randomNumber) {
    var qs = 512>>1;
    this.e = parseInt("10001", 16);
    var ee = new BigInteger("10001", 16);
    for(;;) {
        for(;;) {
            p = new BigInteger(512-qs, 1, randomNumber);
            if(p.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && p.isProbablePrime(10)) break;
        }
        for(;;) {
            q = new BigInteger(qs, 1, randomNumber);
            if(q.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && q.isProbablePrime(10)) break;
        }
        if(p.compareTo(q) <= 0) {
            var t = p;
            p = q;
            q = t;
        }
        var p1 = p.subtract(BigInteger.ONE);
        var q1 = q.subtract(BigInteger.ONE);
        var phi = p1.multiply(q1);
        if(phi.gcd(ee).compareTo(BigInteger.ONE) == 0) {
            //generate some interesting numbers from p and q:
            var qs = 512>>1;		var e = parseInt("10001", 16);  var ee = new BigInteger("10001", 16);
            var p1 = p.subtract(BigInteger.ONE);	var q1 = q.subtract(BigInteger.ONE);
            var phi = p1.multiply(q1);	var n = p.multiply(q);	var d = ee.modInverse(phi);

            return {"n":n.toString(16), "d":d.toString(16)};
        }
    }
}

unhosted.RSAEncrypt = function(text, pubkey) {//copied from the rsa.js script included in Tom Wu's jsbn library
	var n = new BigInteger();	n.fromString(pubkey, 16);
	var m = unhosted.pkcs1pad2(text,(n.bitLength()+7)>>3);	if(m == null) return null;
	var c = m.modPowInt(parseInt("10001", 16), n);	if(c == null) return null;
	var h = c.toString(16);	
	if((h.length & 1) == 0) return h; else return "0" + h;
}

unhosted.RSADecrypt = function(ctext, pubkey, privkey) {//copied from rsa.js script included in Tom Wu's jsbn library
	var c = new BigInteger(ctext, 16);
	var n = new BigInteger();	n.fromString(pubkey, 16);
	var d = new BigInteger();	d.fromString(privkey, 16);
	var m = c.modPow(d, n);
	if(m == null) return null;
	return unhosted.pkcs1unpad2(m, (n.bitLength()+7)>>3);
}

unhosted.RSASign = function(sHashHex, pub, priv) {//this function copied from the rsa.js script included in Tom Wu's jsbn library
	var n = new BigInteger();	n.fromString(pub, 16);
	var sMid = "";	var fLen = (n.bitLength() / 4) - sHashHex.length - 6;
	for (var i = 0; i < fLen; i += 2) {
		sMid += "ff";
	}
	hPM = "0001" + sMid + "00" + sHashHex;//this pads the hash to desired length - not entirely sure whether those 'ff' should be random bytes for security or not
	var x = new BigInteger(hPM, 16);//turn the padded message into a jsbn BigInteger object
	var d = new BigInteger();	d.fromString(priv, 16);
	return x.modPow(d, n);
}

// PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint
unhosted.pkcs1pad2 = function(s,n) {//copied from the rsa.js script included in Tom Wu's jsbn library
	if(n < s.length + 11) {
		alert("Message too long for RSA");
		return null;
	}
	var ba = new Array();
	var i = s.length - 1;
	while(i >= 0 && n > 0) ba[--n] = s.charCodeAt(i--);
	ba[--n] = 0;
	var x = new Array();
	var rng = new SecureRandom();
	while(n > 2) { // random non-zero pad
		x[0] = 0;
		while(x[0] == 0) rng.nextBytes(x);
		ba[--n] = x[0];
	}
	ba[--n] = 2;
	ba[--n] = 0;
	return new BigInteger(ba);
}

// Undo PKCS#1 (type 2, random) padding and, if valid, return the plaintext
unhosted.pkcs1unpad2 = function(d,n) {//copied from the rsa.js script included in Tom Wu's jsbn library
	var b = d.toByteArray();
	var i = 0;
	while(i < b.length && b[i] == 0) ++i;
	if(b.length-i != n-1 || b[i] != 2)
		return null;
	++i;
	while(b[i] != 0)
		if(++i >= b.length) return null;
	var ret = "";
	while(++i < b.length)
		ret += String.fromCharCode(b[i]);
	return ret;
}

unhosted.checkPubSign = function(cmd, PubSign, nick_n) {//check a signature. based on rsa-sign.js. uses Tom Wu's jsbn library.
	var n = new BigInteger();	n.fromString(nick_n, 16);
	var x = new BigInteger(PubSign.replace(/[ \n]+/g, ""), 16);
	return (x.modPowInt(parseInt("10001", 16), n).toString(16).replace(/^1f+00/, '') == sha1.hex(cmd));
}

if(typeof(nodemode) !== "undefined") {
  exports.unhosted = unhosted;
}