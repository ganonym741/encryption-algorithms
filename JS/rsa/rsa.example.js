/**
 * Production-Ready RSA Implementation using Node.js built-in crypto module
 */

const crypto = require('crypto');

class RSA {
    constructor(keySize = 2048) {
        this.keySize = keySize;
        this.keyPair = crypto.generateKeyPairSync('rsa', {
            modulusLength: keySize,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        });
    }
    
    encrypt(plaintext) {
        const encrypted = crypto.publicEncrypt(
            {
                key: this.keyPair.publicKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
            },
            Buffer.from(plaintext, 'utf8')
        );
        
        return encrypted.toString('hex');
    }
    
    decrypt(encrypted) {
        const decrypted = crypto.privateDecrypt(
            {
                key: this.keyPair.privateKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
            },
            Buffer.from(encrypted, 'hex')
        );
        
        return decrypted.toString('utf8');
    }
    
    sign(message) {
        const sign = crypto.createSign('rsa-sha256');
        sign.update(message);
        return sign.sign(this.keyPair.privateKey).toString('hex');
    }
    
    verify(message, signature) {
        const verify = crypto.createVerify('rsa-sha256');
        verify.update(message);
        return verify.verify(this.keyPair.publicKey, Buffer.from(signature, 'hex'));
    }
    
    getPublicKey() {
        return this.keyPair.publicKey;
    }
    
    getPrivateKey() {
        return this.keyPair.privateKey;
    }
}

// Example usage
function example() {
    console.log('===== Production-Ready RSA Example =====');
    
    const rsa = new RSA(2048);
    const plaintext = 'This is a secret message encrypted with production-ready RSA implementation.';
    
    console.log('Plaintext:', plaintext);
    
    const encrypted = rsa.encrypt(plaintext);
    console.log('Encrypted:', encrypted);
    
    const decrypted = rsa.decrypt(encrypted);
    console.log('Decrypted:', decrypted);
    
    console.log('Encryption/Decryption successful:', plaintext === decrypted);
    
    // Test signing and verification
    console.log('\n--- Digital Signature ---');
    const message = 'This is a message to be signed with production-ready RSA implementation.';
    
    const signature = rsa.sign(message);
    console.log('Signature:', signature);
    
    const isValid = rsa.verify(message, signature);
    console.log('Signature verification:', isValid);
    
    // Test with tampered message
    const tamperedMessage = 'This is a tampered message.';
    const isTamperedValid = rsa.verify(tamperedMessage, signature);
    console.log('Tampered message verification:', isTamperedValid);
}

if (require.main === module) {
    example();
}

module.exports = { RSA, example };