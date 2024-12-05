const fs = require('fs');
const crypto = require('crypto');

// Function to convert the public key in PEM format to XML
function publicKeyToXML(pem) {
    const key = crypto.createPublicKey({ key: pem, format: 'pem', type: 'spki' });
    const keyDetails = key.export({ format: 'jwk' });

    const modulus = Buffer.from(keyDetails.n, 'base64').toString('base64');
    const exponent = Buffer.from(keyDetails.e, 'base64').toString('base64');

    return `<RSAKeyValue><Modulus>${modulus}</Modulus><Exponent>${exponent}</Exponent></RSAKeyValue>`;
}


function privateKeyToXML(pem) {
    const key = crypto.createPrivateKey({ key: pem, format: 'pem', type: 'pkcs8' });
    const keyDetails = key.export({ format: 'jwk' });

    const modulus = Buffer.from(keyDetails.n, 'base64').toString('base64');
    const privateExponent = Buffer.from(keyDetails.d, 'base64').toString('base64');
    const prime1 = Buffer.from(keyDetails.p, 'base64').toString('base64');
    const prime2 = Buffer.from(keyDetails.q, 'base64').toString('base64');
    const exp1 = Buffer.from(keyDetails.dp, 'base64').toString('base64');
    const exp2 = Buffer.from(keyDetails.dq, 'base64').toString('base64');
    const coeff = Buffer.from(keyDetails.qi, 'base64').toString('base64');

    return `<RSAKeyValue><Modulus>${modulus}</Modulus><Exponent>AQAB</Exponent><P>${prime1}</P><Q>${prime2}</Q><DP>${exp1}</DP><DQ>${exp2}</DQ><InverseQ>${coeff}</InverseQ><D>${privateExponent}</D></RSAKeyValue>`;
}

// Load the PEM files (public and private)
const publicPem = fs.readFileSync(`${__dirname}/public_key.pem`, 'utf8');
const privatePem = fs.readFileSync(`${__dirname}/private_key.pem`, 'utf8');

// Convert public and private keys to XML
const publicXml = publicKeyToXML(publicPem);
const privateXml = privateKeyToXML(privatePem);

// Save XML output to files
fs.writeFileSync(`${__dirname}/public_key.xml`, publicXml);
fs.writeFileSync(`${__dirname}/private_key.xml`, privateXml);

console.log('Public and Private keys have been converted to XML and saved!');
