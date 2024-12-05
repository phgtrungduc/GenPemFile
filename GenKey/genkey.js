const crypto = require('crypto');
const fs = require('fs');

// Generate RSA key pair for RS256
crypto.generateKeyPair('rsa', {
  modulusLength: 2048,  // Key length in bits
  publicKeyEncoding: {
    type: 'spki',   // Public Key format
    format: 'pem',  // PEM format
  },
  privateKeyEncoding: {
    type: 'pkcs8',  // Private Key format
    format: 'pem',  // PEM format
  }
}, (err, publicKey, privateKey) => {
  if (err) {
    console.error('Error generating key pair:', err);
    return;
  }

  // Save public and private keys to files
  fs.writeFileSync('./public_key.pem', publicKey);
  fs.writeFileSync('./private_key.pem', privateKey);

  console.log('Public and Private keys for RS256 have been generated and saved!');
});
