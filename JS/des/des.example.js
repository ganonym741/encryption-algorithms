/**
 * Production-Ready DES and TripleDES Implementation using Node.js built-in crypto module
 */

const crypto = require('crypto');

class DES {
    constructor(key, algorithm = 'des-ecb') {
        if (!key) {
            throw new Error('DES requires a key');
        }
        
        this.algorithm = algorithm;
        
        // Validate key length based on algorithm
        if (algorithm.includes('des-ecb') || algorithm.includes('des-cbc')) {
            if (key.length !== 8) {
                throw new Error('DES requires an 8-byte key');
            }
        } else if (algorithm.includes('des3')) {
            if (key.length !== 24) {
                throw new Error('TripleDES requires a 24-byte key');
            }
        }
        
        this.key = Buffer.isBuffer(key) ? key : Buffer.from(key, 'utf8');
    }
    
    encrypt(plaintext) {
        const iv = this.algorithm.includes('cbc') ? crypto.randomBytes(8) : null;
        
        try {
            // Try to create cipher with legacy provider option
            const cipher = crypto.createCipheriv(this.algorithm, this.key, iv);
            
            let encrypted = cipher.update(plaintext, 'utf8');
            encrypted = Buffer.concat([encrypted, cipher.final()]);
            
            const result = {
                encrypted: encrypted.toString('hex')
            };
            
            if (iv) {
                result.iv = iv.toString('hex');
            }
            
            return result;
        } catch (error) {
            if (error.code === 'ERR_OSSL_EVP_UNSUPPORTED') {
                throw new Error(`DES algorithm is not supported in this Node.js version. Consider using a more modern encryption algorithm like AES.`);
            }
            throw error;
        }
    }
    
    decrypt(encryptedData) {
        const iv = encryptedData.iv ? Buffer.from(encryptedData.iv, 'hex') : null;
        
        try {
            const decipher = crypto.createDecipheriv(this.algorithm, this.key, iv);
            
            let decrypted = decipher.update(Buffer.from(encryptedData.encrypted, 'hex'));
            decrypted = Buffer.concat([decrypted, decipher.final()]);
            
            return decrypted.toString('utf8');
        } catch (error) {
            if (error.code === 'ERR_OSSL_EVP_UNSUPPORTED') {
                throw new Error(`DES algorithm is not supported in this Node.js version. Consider using a more modern encryption algorithm like AES.`);
            }
            throw error;
        }
    }
}

class TripleDES extends DES {
    constructor(key, mode = 'ecb') {
        const algorithm = `des3-${mode}`;
        super(key, algorithm);
    }
}

// Example usage
function example() {
    console.log('===== Production-Ready DES/TripleDES Example =====');
    
    try {
        // DES Example
        console.log('\n--- DES Example ---');
        const desKey = '8bytekey'; // 8 bytes for DES
        const des = new DES(desKey, 'des-ecb');
        const desPlaintext = 'This is a secret message encrypted with DES.';
        
        console.log('DES Plaintext:', desPlaintext);
        
        const desEncrypted = des.encrypt(desPlaintext);
        console.log('DES Encrypted:', desEncrypted.encrypted);
        
        const desDecrypted = des.decrypt(desEncrypted);
        console.log('DES Decrypted:', desDecrypted);
        
        console.log('DES Encryption/Decryption successful:', desPlaintext === desDecrypted);
        
        // DES with CBC mode
        console.log('\n--- DES-CBC Example ---');
        const desCbc = new DES(desKey, 'des-cbc');
        const desCbcPlaintext = 'This is a secret message encrypted with DES-CBC.';
        
        console.log('DES-CBC Plaintext:', desCbcPlaintext);
        
        const desCbcEncrypted = desCbc.encrypt(desCbcPlaintext);
        console.log('DES-CBC Encrypted:', desCbcEncrypted.encrypted);
        console.log('DES-CBC IV:', desCbcEncrypted.iv);
        
        const desCbcDecrypted = desCbc.decrypt(desCbcEncrypted);
        console.log('DES-CBC Decrypted:', desCbcDecrypted);
        
        console.log('DES-CBC Encryption/Decryption successful:', desCbcPlaintext === desCbcDecrypted);
        
        // TripleDES Example
        console.log('\n--- TripleDES Example ---');
        const tripleDesKey = '24-byte-key-for-triple-des!'; // 24 bytes for TripleDES
        const tripleDes = new TripleDES(tripleDesKey, 'ecb');
        const tripleDesPlaintext = 'This is a secret message encrypted with TripleDES.';
        
        console.log('TripleDES Plaintext:', tripleDesPlaintext);
        
        const tripleDesEncrypted = tripleDes.encrypt(tripleDesPlaintext);
        console.log('TripleDES Encrypted:', tripleDesEncrypted.encrypted);
        
        const tripleDesDecrypted = tripleDes.decrypt(tripleDesEncrypted);
        console.log('TripleDES Decrypted:', tripleDesDecrypted);
        
        console.log('TripleDES Encryption/Decryption successful:', tripleDesPlaintext === tripleDesDecrypted);
        
        // TripleDES with CBC mode
        console.log('\n--- TripleDES-CBC Example ---');
        const tripleDesCbc = new TripleDES(tripleDesKey, 'cbc');
        const tripleDesCbcPlaintext = 'This is a secret message encrypted with TripleDES-CBC.';
        
        console.log('TripleDES-CBC Plaintext:', tripleDesCbcPlaintext);
        
        const tripleDesCbcEncrypted = tripleDesCbc.encrypt(tripleDesCbcPlaintext);
        console.log('TripleDES-CBC Encrypted:', tripleDesCbcEncrypted.encrypted);
        console.log('TripleDES-CBC IV:', tripleDesCbcEncrypted.iv);
        
        const tripleDesCbcDecrypted = tripleDesCbc.decrypt(tripleDesCbcEncrypted);
        console.log('TripleDES-CBC Decrypted:', tripleDesCbcDecrypted);
        
        console.log('TripleDES-CBC Encryption/Decryption successful:', tripleDesCbcPlaintext === tripleDesCbcDecrypted);
        
        // Performance comparison
        console.log('\n--- Performance Comparison ---');
        const { AES } = require('../aes/aes.example');
        const aes = new AES('63f4945d921d599f27ae4fdf5bada3f1');
        
        const largeMessage = 'x'.repeat(1000);
        
        // Measure DES encryption time
        const desStart = process.hrtime.bigint();
        const desEncryptedLarge = des.encrypt(largeMessage);
        const desEnd = process.hrtime.bigint();
        
        // Measure TripleDES encryption time
        const tripleDesStart = process.hrtime.bigint();
        const tripleDesEncryptedLarge = tripleDes.encrypt(largeMessage);
        const tripleDesEnd = process.hrtime.bigint();
        
        // Measure AES encryption time
        const aesStart = process.hrtime.bigint();
        const aesEncryptedLarge = aes.encrypt(largeMessage);
        const aesEnd = process.hrtime.bigint();
        
        const desTime = Number(desEnd - desStart) / 1000000; // Convert to milliseconds
        const tripleDesTime = Number(tripleDesEnd - tripleDesStart) / 1000000; // Convert to milliseconds
        const aesTime = Number(aesEnd - aesStart) / 1000000; // Convert to milliseconds
        
        console.log(`DES encryption time: ${desTime.toFixed(2)} ms`);
        console.log(`TripleDES encryption time: ${tripleDesTime.toFixed(2)} ms`);
        console.log(`AES encryption time: ${aesTime.toFixed(2)} ms`);
        
        console.log(`DES is ${aesTime / desTime}x ${desTime < aesTime ? 'faster' : 'slower'} than AES`);
        console.log(`TripleDES is ${aesTime / tripleDesTime}x ${tripleDesTime < aesTime ? 'faster' : 'slower'} than AES`);
    } catch (error) {
        console.error('DES/TripleDES example failed:', error.message);
        console.log('\nNote: DES and TripleDES are legacy algorithms that have been deprecated in newer Node.js versions.');
        console.log('For production use, please consider using modern encryption algorithms like AES or ChaCha20.');
    }
}

if (require.main === module) {
    example();
}

module.exports = { DES, TripleDES, example };