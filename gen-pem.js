const fs = require('fs');
const { DOMParser } = require('@xmldom/xmldom');

const keyToConvert = "<RSAKeyValue><Modulus>sBxoiezoLcFiVRPU6r8QFuUVJsXI+6hIlMSEDs9RgqK/h07I36H/fu099aGQ2EcuH33pTr85Ig8nQh0G0spGgQpWbzppXJILzItxrCzfDvXIJ4AyW9zuOEX8hkXy+agq8x8l5lIK2bEBMOJ2fzuW4m7Ynlfx8MfS0PqtASwcS9R0lDR1HCXVPeMrjfR2b5pcWe2ccoORPb2nK7+abnAaQGaycyKtYri4rPn43wuFk2XsdeB1kD9+BUKQ/FW57v0BLjT7OMCanxYLtes6qT4ayILyM/jADmUluy2D8jtYVL/4jSTi0V2fWrt5Vwez5AP1dPY+IEYqRuCaSVNTRr98zw==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>"


function generatePemFromRsaKeyValue(xmlString) {
    // Parse the XML string
    const parser = new DOMParser();
    const xmlDoc = parser.parseFromString(xmlString, 'text/xml');

    // Extract Modulus and Exponent
    const modulusBase64 = xmlDoc.getElementsByTagName('Modulus')[0].textContent;
    const exponentBase64 = xmlDoc.getElementsByTagName('Exponent')[0].textContent;

    // Convert Base64 to Buffer
    const modulusBuffer = Buffer.from(modulusBase64, 'base64');
    const exponentBuffer = Buffer.from(exponentBase64, 'base64');

      // Construct the ASN.1 DER encoding for the public key
      const modulusLength = modulusBuffer.length;
      const exponentLength = exponentBuffer.length;
  
      const totalLength = 2 + modulusLength + 2 + exponentLength + 2; // Sequence size
      const derBuffer = Buffer.alloc(2 + totalLength);
  
      // Write the sequence header
      let offset = 0;
      derBuffer[offset++] = 0x30; // Sequence tag
      derBuffer[offset++] = totalLength;
  
      // Write the modulus
      derBuffer[offset++] = 0x02; // Integer tag
      derBuffer[offset++] = modulusLength;
      modulusBuffer.copy(derBuffer, offset);
      offset += modulusLength;
  
      // Write the exponent
      derBuffer[offset++] = 0x02; // Integer tag
      derBuffer[offset++] = exponentLength;
      exponentBuffer.copy(derBuffer, offset);
  
      // Convert the DER buffer to PEM format
      const derBase64 = derBuffer.toString('base64');
      const pemKey = [
          '-----BEGIN RSA PUBLIC KEY-----',
          derBase64.match(/.{1,64}/g).join('\n'), // Split Base64 into lines of 64 characters
          '-----END RSA PUBLIC KEY-----',
      ].join('\n');
  
      // Write the PEM key to the output file
      fs.writeFileSync("pem", pemKey);
  
      console.log(`PEM file created`);
}

generatePemFromRsaKeyValue(keyToConvert);