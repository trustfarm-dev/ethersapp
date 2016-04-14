/**
 * Wallet
 *
 * A wallet manages an Ethereum private key and uses the key to
 * sign transactions to be sent to Ethereum smart contracts
 *
 */

function Wallet(privateKey) {
  var key;
  if( typeof privateKey === 'string' ) {
    console.log('converting private key to buffer');
    key = new Buffer(ethUtil.stripHexPrefix(privateKey), 'hex');
  }
  else {
    console.log('no need to convert private key to buffer');
    key = privateKey; 
  }
 
  this._privateKey = key;
}



Wallet.getValue = function(json, path) {
  var current = json;

  var parts = path.split('/');
  for (var i = 0; i < parts.length; i++) {
    var search = parts[i].toLowerCase();
    var found = null;
    for (var key in current) {
      if (key.toLowerCase() === search) {
        found = key;
        break;
      }
    }
    if (found === null) {
      return null;
    }
    current = current[found];
  }
  return current;
}


Wallet.importFromJson = function (json, password, callback){

  console.log('In wallet.importFromJson');
  if( !json ) {
    callback(new Error('json is missing'));
    return;
  }
  if( typeof json === 'string' ) {
    try {
      json = JSON.parse(json);
    } catch (err) {
      callback (new Error("Invalid JSON Wallet"));
      return;
    }
  }


  // Derive the key
  var kdf = Wallet.getValue(json, "crypto/kdf");
  if (kdf && kdf.toLowerCase() === "scrypt") {

  // Scrypt parameters
  var saltString = Wallet.getValue(json, 'crypto/kdfparams/salt');
  if( !saltString ) throw new Error('salt is missing in json file.'); 
  var salt = new Buffer(saltString, 'hex');
  var N = Wallet.getValue(json, 'crypto/kdfparams/n');
  var r = Wallet.getValue(json, 'crypto/kdfparams/r');
  var p = Wallet.getValue(json, 'crypto/kdfparams/p');
  if (!N || !r || !p) {
    callback(new Error("Invalid JSON Wallet (bad kdfparams)"));
    return;
  }

  // We need exactly 32 bytes of derived key
  var dkLen = Wallet.getValue(json, 'crypto/kdfparams/dklen');
  if (dkLen !== 32) {
    callback(new Error("Invalid JSON Wallet (dkLen != 32)"));
  }

  // Derive the key, calling the callback periodically with progress updates
  
  if( !password ) password = '';
  var passwordBytes = new Buffer(password, 'utf8');
  var stop; 
  var wallet;
  var key = null;
  scrypt(passwordBytes, salt, N, r, p, dkLen, function(error, progress, key) {
 
    if( error ) {
      console.log('scrypt error:', error );
    }
    if( !error ) {
      if( key ) {
        try {
          wallet = Wallet.decryptWallet(key, json);
          console.log( 'got new wallet');
        } catch (err) {
          error = err;    
        }
      }
    }
    stop = callback( error, progress, wallet );
    return stop;  // tell scrypt if user cancelled the operation
      
  });
  } else {
    console.log('kdf value', kdf, json);
    callback(new Error("Unsupported key derivation function"));
  }
}

Wallet.decryptWallet = function(derivedKey, json) {
  // Check the password is correct
  console.log('in decryptWallet', derivedKey);
  var ciphertext = Wallet.getValue(json, "crypto/ciphertext");
  if( !ciphertext ) throw new Error('ciphertext is missing in json file.'); 
  var cipherhex = new Buffer(ciphertext, 'hex');
  console.log('in decryptWallet calling concat');
  if( !Buffer.isBuffer(derivedKey) ) {
     console.log( 'converting derived key to buffer');
     derivedKey = new Buffer(derivedKey);
  }
  var mac = ethUtil.sha3(Buffer.concat([derivedKey.slice(16, 32), cipherhex])).toString('hex');
  console.log('in decryptWallet after concat');
  var macWallet = Wallet.getValue(json, 'crypto/mac').toLowerCase();
  if (mac.toLowerCase() !== macWallet) {
    throw new Error('Message Authentication Code mismatch (wrong password)');
  }

  key = derivedKey.slice(0, 16);
  var seed = null;

  var cipher = Wallet.getValue(json, 'crypto/cipher');
  if (cipher === 'aes-128-ctr') {
    var iv = Wallet.getValue(json, 'crypto/cipherparams/iv');
    if( !iv ) throw new Error('iv is missing.'); 
    var ivBytes = new Buffer(iv, 'hex');
    var counter;
    try {
      counter = new aesjs.Counter(ivBytes);
    } catch (err) {
      throw new Error('new aesjs counter error' + err);
    }

    var aes ;
    try {
      aes = new aesjs.ModeOfOperation.ctr(key, counter);
    } catch (err) {
      throw new Error('new aesjs mode of operation error' + err);
    }

    try {
      seed = aes.decrypt(cipherhex);
    } catch (err) {
      throw new Error('new aesjs decrypt error: ' + err);
    }

  } else {
    throw new Error("Unsupported cipher algorithm");
  }


  var address = ethUtil.privateToAddress(seed).toString('hex');
  var addressJson = Wallet.getValue(json, 'address'); 
  console.log('addr=' + address + ' jsonAdr= ' + addressJson);
  if( address !== addressJson ) {
    throw new Error("Invalid address for the private key");
  }
  
  var wallet = Wallet.importFromKey(seed);
  return wallet;
}

Wallet.importFromKey = function(key) {
  var wallet = new Wallet(key);
  return wallet;
}

/**
 *  signs a transaction and returns the serialized string
 */
Wallet.prototype.sign = function (txObject){

  if( !this._privateKey ) {
    throw new Error('Private key is not available, import wallet to load the private key');
  }
  var tx = new EthTx(txObject);
  tx.sign(this._privateKey);
  var serializedTx = tx.serialize();
  return serializedTx;
}

Wallet.prototype.getAddress = function (){
  var address = '';
  if( this._privateKey ) {
    var rawAddress = ethUtil.privateToAddress(this._privateKey).toString('hex');
    address = ethUtil.addHexPrefix(ethUtil.padToEven(rawAddress));
  }
  return address;
}

Wallet.prototype.clearPrivateKey = function() {
  this._privateKey = null;
}
