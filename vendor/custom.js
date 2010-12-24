	var RSAEncrypt = function(text, pubkey) {//copied from the rsa.js script included in Tom Wu's jsbn library
		/*
    if((typeof keys[nick] === 'undefined') || (typeof keys[nick].n === 'undefined')) {
			alert("user "+nick+" doesn't look like a valid unhosted account");
		}
    */
		var n = new BigInteger();	n.fromString(pubkey, 16);
		var m = pkcs1pad2(text,(n.bitLength()+7)>>3);	if(m == null) return null;
		var c = m.modPowInt(parseInt("10001", 16), n);	if(c == null) return null;
		var h = c.toString(16);	
		if((h.length & 1) == 0) return h; else return "0" + h;
	}

	var RSADecrypt = function(ctext, pubkey, privkey) {//copied from rsa.js script included in Tom Wu's jsbn library
		var c = new BigInteger(ctext, 16);
		var n = new BigInteger();	n.fromString(pubkey, 16);
		var d = new BigInteger();	d.fromString(privkey, 16);
		var m = c.modPow(d, n);
		if(m == null) return null;
		return pkcs1unpad2(m, (n.bitLength()+7)>>3);
	}
