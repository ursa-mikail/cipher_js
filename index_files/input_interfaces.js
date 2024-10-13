
// t1
    function t1(message) {
    document.getElementById("key").innerHTML="";
        var digest = CryptoJS.MD5(message);
        document.getElementById("hash").innerHTML = "Type:\t\tMD5";
        document.getElementById("hash").innerHTML += "\nMessage:\t" + message;
        document.getElementById("hash").innerHTML += "\nHex:\t" + digest;
        document.getElementById("hash").innerHTML += "\nBase64:\t" + CryptoJS.enc.Base64.stringify(digest);
    }
// t2
    function t2(message) {
    document.getElementById("key").innerHTML="";
        var digest = CryptoJS.SHA1(message);
        document.getElementById("hash").innerHTML = "Type:\t\tSHA1";
        document.getElementById("hash").innerHTML += "\nMessage:\t" + message;

        document.getElementById("hash").innerHTML += "\nHex:\t" + digest;
        document.getElementById("hash").innerHTML += "\nBase64:\t" + CryptoJS.enc.Base64.stringify(digest);

    }
// t3
    function t3(message) {
    document.getElementById("key").innerHTML="";
        var digest = CryptoJS.SHA256(message);

        document.getElementById("hash").innerHTML = "Type:\t\tSHA256";
        document.getElementById("hash").innerHTML += "\nMessage:\t" + message;

        document.getElementById("hash").innerHTML += "\nHex:\t" + digest;
        document.getElementById("hash").innerHTML += "\nBase64:\t" + CryptoJS.enc.Base64.stringify(digest);

    }

    function t3b(message) {
    document.getElementById("key").innerHTML="";
        var digest = CryptoJS.SHA512(message);

        document.getElementById("hash").innerHTML = "Type:\t\tSHA512";
        document.getElementById("hash").innerHTML += "\nMessage:\t" + message;

        document.getElementById("hash").innerHTML += "\nHex:\t" + digest;
        document.getElementById("hash").innerHTML += "\nBase64:\t" + CryptoJS.enc.Base64.stringify(digest);

    }

    function t3a(message) {
        var hash1 = CryptoJS.SHA3(message, { outputLength: 224 }).toString();
        var hash2 = CryptoJS.SHA3(message, { outputLength: 256 }).toString();
        var hash3 = CryptoJS.SHA3(message, { outputLength: 384 }).toString();
        var hash4 = CryptoJS.SHA3(message, { outputLength: 512 }).toString();

        document.getElementById("hash").innerHTML = "Type:\t\tSHA3 (Keccak)";
        document.getElementById("hash").innerHTML += "\nMessage:\t" + message;

        document.getElementById("hash").innerHTML += "\nHex (224-bit):\t" + hash1;
        document.getElementById("hash").innerHTML += "\nHex (256-bit):\t" + hash2;
        document.getElementById("hash").innerHTML += "\nHex (384-bit):\t" + hash3;
        document.getElementById("hash").innerHTML += "\nHex (512-bit):\t" + hash4;
    }

    function t3c(message) {
    document.getElementById("key").innerHTML="";
        var digest = CryptoJS.RIPEMD160(message);

        document.getElementById("hash").innerHTML = "Type:\t\tRIPEM160";
        document.getElementById("hash").innerHTML += "\nMessage:\t" + message;

        document.getElementById("hash").innerHTML += "\nHex:\t" + digest;
        document.getElementById("hash").innerHTML += "\nBase64:\t" + CryptoJS.enc.Base64.stringify(digest);
    }

// t4
    function t4(message, password) {
    document.getElementById("key").innerHTML="";
        document.getElementById("hash").innerHTML = "Type:\t\tAES (CBC)";
        document.getElementById("hash").innerHTML += "\nMessage:\t" + message;
        document.getElementById("hash").innerHTML += "\nPassword:\t" + password;

        var crypted = CryptoJS.AES.encrypt(message, password,"{ mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }");
        var plain = CryptoJS.AES.decrypt(crypted, password,"{ mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }");

        var saltHex = crypted.salt.toString();     // random salt
        var ivHex = crypted.iv.toString();
        var key = crypted.key.toString();

        document.getElementById("hash").innerHTML += "\nSalt:\t\t" + saltHex;
        document.getElementById("hash").innerHTML += "\nIV:\t\t" + ivHex;
        document.getElementById("hash").innerHTML += "\nKey:\t\t" + key;

        document.getElementById("hash").innerHTML += "\nEncrypted:\t"+crypted;
        document.getElementById("hash").innerHTML += "\nDecrypted:\t" + plain.toString(CryptoJS.enc.Utf8);

    }

    function t4a(message, password) {
    document.getElementById("key").innerHTML="";
        document.getElementById("hash").innerHTML = "Type:\t\tAES (ECB)";
        document.getElementById("hash").innerHTML += "\nMessage:\t" + message;
        document.getElementById("hash").innerHTML += "\nPassword:\t" + password;

        var crypted = CryptoJS.AES.encrypt(message, password, "{ mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 }");
        var plain = CryptoJS.AES.decrypt(crypted, password, "{ mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 }");
        // Other padding: Pkcs7; Iso97971; AnsiX923; Iso10126; ZeroPadding; and NoPadding -->

        var saltHex = crypted.salt.toString();     // random salt
        var ivHex = crypted.iv.toString();
        var Key = crypted.key.toString();

        document.getElementById("hash").innerHTML += "\nSalt:\t\t" + saltHex;
        document.getElementById("hash").innerHTML += "\nIV:\t\t" + ivHex;
        document.getElementById("hash").innerHTML += "\nKey:\t\t" + Key;

        document.getElementById("hash").innerHTML += "\nEncrypted:\t" + crypted;
        document.getElementById("hash").innerHTML += "\nDecrypted:\t" + plain.toString(CryptoJS.enc.Utf8);

    }

    function t4b(message, password) {
    document.getElementById("key").innerHTML="";
        document.getElementById("hash").innerHTML = "Type:\t\tAES (CFB)";
        document.getElementById("hash").innerHTML += "\nMessage:\t" + message;
        document.getElementById("hash").innerHTML += "\nPassword:\t" + password;

        var crypted = CryptoJS.AES.encrypt(message, password, "{ mode: CryptoJS.mode.CFB, padding: CryptoJS.pad.AnsiX923 }");

        var plain = CryptoJS.AES.decrypt(crypted, password, "{ mode: CryptoJS.mode.CFB, padding: CryptoJS.pad.AnsiX923 }");
        // Other padding: Pkcs7; Iso97971; AnsiX923; Iso10126; ZeroPadding; and NoPadding -->

        var saltHex = crypted.salt.toString();     // random salt
        var ivHex = crypted.iv.toString();
        var Key = crypted.key.toString();

        document.getElementById("hash").innerHTML += "\nSalt:\t\t" + saltHex;
        document.getElementById("hash").innerHTML += "\nIV:\t\t" + ivHex;
        document.getElementById("hash").innerHTML += "\nKey:\t\t" + Key;

        document.getElementById("hash").innerHTML += "\nEncrypted:\t" + crypted;
        document.getElementById("hash").innerHTML += "\nDecrypted:\t" + plain.toString(CryptoJS.enc.Utf8);

    }

    function t4c(message, password) {
    document.getElementById("key").innerHTML="";
        document.getElementById("hash").innerHTML = "Type:\t\tAES (CRT)";
        document.getElementById("hash").innerHTML += "\nMessage:\t" + message;
        document.getElementById("hash").innerHTML += "\nPassword:\t" + password;

        var crypted = CryptoJS.AES.encrypt(message, password, "{ mode: CryptoJS.mode.CRT, padding: CryptoJS.pad.AnsiX923 }");

        var plain = CryptoJS.AES.decrypt(crypted, password, "{ mode: CryptoJS.mode.CRT, padding: CryptoJS.pad.AnsiX923 }");
        // Other padding: Pkcs7; Iso97971; AnsiX923; Iso10126; ZeroPadding; and NoPadding -->
        var saltHex = crypted.salt.toString();     // random salt
        var ivHex = crypted.iv.toString();

        document.getElementById("hash").innerHTML += "\nSalt:\t\t" + saltHex;
        document.getElementById("hash").innerHTML += "\nIV:\t\t" + ivHex;

        document.getElementById("hash").innerHTML += "\nEncrypted:\t" + crypted;
        document.getElementById("hash").innerHTML += "\nDecrypted:\t" + plain.toString(CryptoJS.enc.Utf8);

    }

    function t4d(message, password) {
    document.getElementById("key").innerHTML="";
        document.getElementById("hash").innerHTML = "Type:\t\tAES (OFB)";
        document.getElementById("hash").innerHTML += "\nMessage:\t" + message;
        document.getElementById("hash").innerHTML += "\nPassword:\t" + password;

        var crypted = CryptoJS.AES.encrypt(message, password, "{ mode: CryptoJS.mode.OFB, padding: CryptoJS.pad.AnsiX923 }");

        var plain = CryptoJS.AES.decrypt(crypted, password, "{ mode: CryptoJS.mode.OFB, padding: CryptoJS.pad.AnsiX923 }");
        // Other padding: Pkcs7; Iso97971; AnsiX923; Iso10126; ZeroPadding; and NoPadding -->

        var saltHex = crypted.salt.toString();     // random salt
        var ivHex = crypted.iv.toString();

        document.getElementById("hash").innerHTML += "\nSalt:\t\t" + saltHex;
        document.getElementById("hash").innerHTML += "\nIV:\t\t" + ivHex;
        document.getElementById("hash").innerHTML += "\nEncrypted:\t" + crypted;
        document.getElementById("hash").innerHTML += "\nDecrypted:\t" + plain.toString(CryptoJS.enc.Utf8);

    }

// t5
   function t5(message, password) {
    document.getElementById("key").innerHTML="";
        document.getElementById("hash").innerHTML = "Type:\t\tRabbit";
        document.getElementById("hash").innerHTML += "\nMessage:\t" + message;
        document.getElementById("hash").innerHTML += "\nPassword:\t" + password;

        var crypted = CryptoJS.Rabbit.encrypt(message, password);

        var plain = CryptoJS.Rabbit.decrypt(crypted, password);

        var saltHex = crypted.salt.toString();     // random salt
        var ivHex = crypted.iv.toString();

        document.getElementById("hash").innerHTML += "\nSalt:\t\t" + saltHex;
        document.getElementById("hash").innerHTML += "\nIV:\t\t" + ivHex;
        document.getElementById("hash").innerHTML += "\nEncrypted:\t" + crypted;
        document.getElementById("hash").innerHTML += "\nDecrypted:\t" + plain.toString(CryptoJS.enc.Utf8);

    }

// t6
    function t6(message, password) {
    document.getElementById("key").innerHTML="";
        var crypted = CryptoJS.RC4.encrypt(message, password);

        var plain = CryptoJS.RC4.decrypt(crypted, password);
        document.getElementById("hash").innerHTML = "Type:\t\tRC4";
        document.getElementById("hash").innerHTML += "\nMessage:\t" + message;
        document.getElementById("hash").innerHTML += "\nPassword:\t" + password;

        var saltHex = crypted.salt.toString();     // random salt
        var ivHex = crypted.iv.toString();

        document.getElementById("hash").innerHTML += "\nSalt:\t\t" + saltHex;
        document.getElementById("hash").innerHTML += "\nIV:\t\t" + ivHex;

        document.getElementById("hash").innerHTML += "\nEncrypted:\t" + crypted;
        document.getElementById("hash").innerHTML += "\nDecrypted:\t" + plain;

    }

    function t6b(message, password) {
    document.getElementById("key").innerHTML="";
        var crypted = CryptoJS.DES.encrypt(message, password);

        var plain = CryptoJS.DES.decrypt(crypted, password);
        document.getElementById("hash").innerHTML = "Type:\t\tDES";
        document.getElementById("hash").innerHTML += "\nMessage:\t" + message;
        document.getElementById("hash").innerHTML += "\nPassword:\t" + password;

        var saltHex = crypted.salt.toString();     // random salt
        var ivHex = crypted.iv.toString();

        document.getElementById("hash").innerHTML += "\nSalt:\t\t" + saltHex;
        document.getElementById("hash").innerHTML += "\nIV:\t\t" + ivHex;

        document.getElementById("hash").innerHTML += "\nEncrypted:\t" + crypted;
        document.getElementById("hash").innerHTML += "\nDecrypted:\t" + plain;

    }

    function t6b_2(message, password) {
    document.getElementById("key").innerHTML="";
        var crypted = CryptoJS.TripleDES.encrypt(message, password);

        var plain = CryptoJS.TripleDES.decrypt(crypted, password);
        document.getElementById("hash").innerHTML = "Type:\t\t3DES";
        document.getElementById("hash").innerHTML += "\nMessage:\t" + message;
        document.getElementById("hash").innerHTML += "\nPassword:\t" + password;

        var saltHex = crypted.salt.toString();     // random salt
        var ivHex = crypted.iv.toString();

        document.getElementById("hash").innerHTML += "\nSalt:\t\t" + saltHex;
        document.getElementById("hash").innerHTML += "\nIV:\t\t" + ivHex;

        document.getElementById("hash").innerHTML += "\nEncrypted:\t" + crypted;
        document.getElementById("hash").innerHTML += "\nDecrypted:\t" + plain;
    }

// t7
    function t7(message, password) {
    document.getElementById("key").innerHTML="";
        var hash = CryptoJS.HmacMD5(message, password);
        var output = hash.toString(CryptoJS.enc.Hex);

        document.getElementById("hash").innerHTML = "Type:\t\tHMAC-MD5";
        document.getElementById("hash").innerHTML += "\nMessage:\t" + message;
        document.getElementById("hash").innerHTML += "\nPassword:\t" + password;

        document.getElementById("hash").innerHTML += "\nHex:\t" + output;
        document.getElementById("hash").innerHTML += "\nBase64:\t" + CryptoJS.enc.Base64.stringify(hash);
    }
// t8
    function t8(message, password) {
    document.getElementById("key").innerHTML="";
        var hash = CryptoJS.HmacSHA1(message, password);
        var output = hash.toString(CryptoJS.enc.Hex);

        document.getElementById("hash").innerHTML = "Type:\t\tHMAC-SHA1";
        document.getElementById("hash").innerHTML += "\nMessage:\t" + message;
        document.getElementById("hash").innerHTML += "\nPassword:\t" + password;

        document.getElementById("hash").innerHTML += "\nHex:\t" + output;
        document.getElementById("hash").innerHTML += "\nBase64:\t" +  CryptoJS.enc.Base64.stringify(hash);
    }
// t9
    function t9c(message, password) {
    document.getElementById("key").innerHTML="";
        var hash = CryptoJS.HmacSHA256(message, password);
        var output = hash.toString(CryptoJS.enc.Hex);

        document.getElementById("hash").innerHTML = "Type:\t\tHMAC-SHA256";
        document.getElementById("hash").innerHTML += "\nMessage:\t" + message;
        document.getElementById("hash").innerHTML += "\nPassword:\t" + password;

        document.getElementById("hash").innerHTML += "\nHex:\t" + output;
        document.getElementById("hash").innerHTML += "\nBase64:\t" + CryptoJS.enc.Base64.stringify(hash);

    }

    function t9(message, password) {
    document.getElementById("key").innerHTML="";
        var hash = CryptoJS.HmacSHA512(message, password);
        var output = hash.toString(CryptoJS.enc.Hex);

        document.getElementById("hash").innerHTML = "Type:\t\tHMAC-SHA512";
        document.getElementById("hash").innerHTML += "\nMessage:\t" + message;
        document.getElementById("hash").innerHTML += "\nPassword:\t" + password;

        document.getElementById("hash").innerHTML += "\nHex:\t" + output;
        document.getElementById("hash").innerHTML += "\nBase64:\t" + CryptoJS.enc.Base64.stringify(hash);
    }

    function t9a(message, password) {
    document.getElementById("key").innerHTML="";
        var hash = CryptoJS.HmacSHA3(message, password);
        var output = hash.toString(CryptoJS.enc.Hex);

        document.getElementById("hash").innerHTML = "Type:\t\tHMAC-SHA3";
        document.getElementById("hash").innerHTML += "\nMessage:\t" + message;
        document.getElementById("hash").innerHTML += "\nPassword:\t" + password;

        document.getElementById("hash").innerHTML += "\nHex:\t" + output;
        document.getElementById("hash").innerHTML += "\nBase64:\t" +  CryptoJS.enc.Base64.stringify(hash);
    }

    function t9b(message, password) {
    document.getElementById("key").innerHTML="";

        var hash = CryptoJS.HmacRIPEMD160(message, password);
        var output = hash.toString(CryptoJS.enc.Hex);

        document.getElementById("hash").innerHTML = "Type:\t\tHMAC-RIPEMD160";
        document.getElementById("hash").innerHTML += "\nMessage:\t" + message;
        document.getElementById("hash").innerHTML += "\nPassword:\t" + password;

        document.getElementById("hash").innerHTML += "\nHex:\t" + output;

        document.getElementById("hash").innerHTML += "\nBase64:\t" + CryptoJS.enc.Base64.stringify(hash);
    }
// t10
    function t10(message) {
    document.getElementById("key").innerHTML="";

        salt = CryptoJS.lib.WordArray.random(128 / 8);

        var key128Bits = CryptoJS.PBKDF2(message, salt, { keySize: 128 / 32 });

        var key256Bits = CryptoJS.PBKDF2(message, salt, { keySize: 256 / 32 });
        var key512Bits = CryptoJS.PBKDF2(message, salt, { keySize: 512 / 32 });

 //       var key512bit1000 = CryptoJS.PBKDF2(message, salt, 64, { iterations: 1000 });
        document.getElementById("hash").innerHTML = "Type:\t\tPBKDF2";
        document.getElementById("hash").innerHTML += "\nMessage:\t" + message;

        document.getElementById("hash").innerHTML += "\nSalt:\t\t" + salt;
        document.getElementById("hash").innerHTML += "\n128-bit:\t"+String(key128Bits);
        document.getElementById("hash").innerHTML += "\n256-bit:\t" + String(key256Bits);
        document.getElementById("hash").innerHTML += "\n512-bit:\t" + String(key512Bits);
//        document.getElementById("hash").innerHTML += "\n512-bit (1000:\t" + key512bit1000;
    }

    function t10a(password) {
    document.getElementById("key").innerHTML="";

        salt = CryptoJS.lib.WordArray.random(128 / 8);

        var key1 = CryptoJS.EvpKDF(password, salt, { keySize: 4 });
        var key2 = CryptoJS.EvpKDF(password, salt, { keySize: 8 });

        document.getElementById("hash").innerHTML = "Type:\t\tEvpKDF";
        document.getElementById("hash").innerHTML += "\nPassword:\t" + password;

        document.getElementById("hash").innerHTML += "\nSalt:\t\t" + salt;
        document.getElementById("hash").innerHTML += "\n128-bit key:\t" + String(key1);
        document.getElementById("hash").innerHTML += "\n256-bit key:\t" + String(key2);
       //        document.getElementById("hash").innerHTML += "\n512-bit (1000:\t" + key512bit1000;
    }
// t11
    function t11(word, password) {
    document.getElementById("key").innerHTML="";
        n = '0000000000000000';
        k = String(CryptoJS.SHA256(password));

        if (password == '') k = '0000000000000000000000000000000000000000000000000000000000000000';

        n1 = hexStringToByte(n);
        k1 = hexStringToByte(k);

        var ctx, out;

        out = new Array(word.length);
        ctx = chacha20_init(k1, n1);

        chacha20_keystream(ctx, out, out, word.length);

        document.getElementById("hash").innerHTML = "Type:\t\tChaCha20";
        document.getElementById("hash").innerHTML += "\nInput:\t\t" + word;
        document.getElementById("hash").innerHTML += "\nPassword:\t" + password;
        document.getElementById("hash").innerHTML += "\nKey seed: " + k +"\n (based on SHA-256 of "+password+")";

        document.getElementById("hash").innerHTML += "\nKey stream:\t" + bytes2hex(out) + " (based on length of "+ word + ")";
        document.getElementById("hash").innerHTML += "\nText stream:\t" + ascii_to_hexa(word);

        var dat = [];
        for (var i = 0; i < word.length; i++) {
            dat.push(word.charCodeAt(i));
        }

        val1 = xor(dat, out);

        document.getElementById("hash").innerHTML += "\nOutput stream:\t" + toHexString(val1);
    }
// t12
    function t12(word, password) {
    document.getElementById("key").innerHTML="";
        k = String(CryptoJS.SHA256(password));
        k1 = hexStringToByte(k);

        var s = new poly1305(k1);
        mpos = 0;

        var m = hexStringToByte(ascii_to_hexa(word));

        s.update(m, mpos, m.length);

        out = new Uint16Array(16);
        s.finish(out, 0);

        document.getElementById("hash").innerHTML = "Type\t\tPoly1305";
        document.getElementById("hash").innerHTML += "\nInput:\t\t" + word;
        document.getElementById("hash").innerHTML += "\nPassword:\t" + password;
        document.getElementById("hash").innerHTML += "\nInput (Hex):\t" + k;
        document.getElementById("hash").innerHTML += "\nPassword (Hex):\t" + ascii_to_hexa(word);
        document.getElementById("hash").innerHTML += "\nTag:\t\t" + toHexString(out);
    }
// t13
    function t13(word, password) {
    document.getElementById("key").innerHTML="";

        k = "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b";
        k1 = hexStringToByte(k);

        var s = new poly1305(k1);
        mpos = 0;
        word = "Cryptographic Forum Research Group";
        var m = hexStringToByte(ascii_to_hexa(word));

        s.update(m, mpos, m.length);

        out = new Uint16Array(16);
        s.finish(out, 0);

        document.getElementById("hash").innerHTML = "Type\t\tPoly1305";
        document.getElementById("hash").innerHTML += "\nInput:\t\t" + word;

        document.getElementById("hash").innerHTML += "\nInput (Hex):\t" + k;
        document.getElementById("hash").innerHTML += "\nPassword (Hex):\t" + ascii_to_hexa(word);
        document.getElementById("hash").innerHTML += "\nTag:\t\t" + toHexString(out);
    }

// t_rsa
   function trsa(word,keySize) {
       // var keySize =1024;
        var dt = new Date();
        var time = -(dt.getTime());
        var crypt = new JSEncrypt({ default_key_size: keySize });

        crypt.getKey();
        dt = new Date();
        time += (dt.getTime());

        document.getElementById("key").innerHTML="";
        document.getElementById("key").innerHTML += 'Key generated in ' + time + ' ms';
        document.getElementById("key").innerHTML += "\nPrivate key:\n" +crypt.getPrivateKey();
        document.getElementById("key").innerHTML += "\nPublic key:\n" +crypt.getPublicKey();

        var dt = new Date();
        var time = -(dt.getTime());

        var cipher = crypt.encrypt(word);
        var decipher = crypt.decrypt(cipher);
        dt = new Date();
        time += (dt.getTime());
        document.getElementById("hash").innerHTML="";
        document.getElementById("hash").innerHTML += 'Encrypt/decrypt in ' + time + ' ms';
        document.getElementById("hash").innerHTML += "\nText:\t" +word;

        document.getElementById("hash").innerHTML += "\nEncrypt with public key:\t" +cipher;
        document.getElementById("hash").innerHTML += "\nDecrypt with private key:\t"+ decipher;
    }

// t_ecc
   function do_pub(etype) {
    do_init();
    set_ec_params(etype);
        a = pick_rand();
        var before = new Date();
        var curve = get_curve();

        var G = get_G(curve);
        var P = G.multiply(a);

        var after = new Date();

     document.getElementById('hash').innerHTML ='';
     document.getElementById("hash").innerHTML += 'Type: ' +  etype;

       document.getElementById("key").innerHTML="";
        document.getElementById("key").innerHTML += 'Public Key generated in ' +  (after - before)  + ' ms';

        document.getElementById('key').innerHTML += '\nPrivate key: '+a;
        document.getElementById('key').innerHTML += '\nPublic key(x): '+P.getX().toBigInteger().toString();
        document.getElementById('key').innerHTML += '\nPublic key(y): '+P.getY().toBigInteger().toString();

      document.getElementById('key').innerHTML += '\n\n==Parameters====';

        document.getElementById('key').innerHTML += '\na: '+aval;
        document.getElementById('key').innerHTML += '\nb: '+bval;
        document.getElementById('key').innerHTML += '\nGx: '+G.getX().toBigInteger().toString();
        document.getElementById('key').innerHTML += '\nGy: '+G.getY().toBigInteger().toString();
    }



