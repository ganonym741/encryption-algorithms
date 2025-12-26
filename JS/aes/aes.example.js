/**
 * Production-Ready AES Implementation using Node.js built-in crypto module
 */

const crypto = require('crypto');

class AES {
    constructor(key) {
        if (!key || key.length !== 32) {
            throw new Error('AES-256 requires a 32-byte key');
        }
        this.key = Buffer.isBuffer(key) ? key : Buffer.from(key, 'utf8');
    }
    
    encrypt(plaintext) {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', this.key, iv);
        
        let encrypted = cipher.update(plaintext, 'utf8');
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        
        return {
            iv,
            encrypted: encrypted.toString('hex')
        };
    }
    
    decrypt(encryptedData) {
        const decipher = crypto.createDecipheriv('aes-256-cbc', this.key, encryptedData.iv);
        
        let decrypted = decipher.update(Buffer.from(encryptedData.encrypted, 'hex'));
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        
        return decrypted.toString('utf8');
    }
}

// Example usage
function example() {
    console.log('===== Production-Ready AES Example =====');
    
    const aes = new AES('63f4945d921d599f27ae4fdf5bada3f1');
    const plaintext = 'This is a secret message encrypted with production-ready AES implementation.';
    
    console.log('Plaintext:', plaintext);
    
    const encrypted = aes.encrypt(plaintext);
    console.log('Encrypted:', encrypted.encrypted);
    console.log('IV:', encrypted.iv);
    
    const decrypted = aes.decrypt(encrypted);
    console.log('Decrypted:', decrypted);
    
    console.log('Encryption/Decryption successful:', plaintext === decrypted);
}

if (require.main === module) {
    example();
}

module.exports = { AES, example };