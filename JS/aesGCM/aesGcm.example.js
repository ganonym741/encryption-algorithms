/**
 * Production-Ready AES-GCM Implementation using Node.js built-in crypto module
 */

const crypto = require('crypto');

class AESGCM {
    constructor(key) {
        if (!key || key.length !== 32) {
            throw new Error('AES-256-GCM requires a 32-byte key');
        }
        this.key = Buffer.isBuffer(key) ? key : Buffer.from(key, 'utf8');
    }
    
    encrypt(plaintext, associatedData = null) {
        const iv = crypto.randomBytes(12); // GCM recommended IV size is 12 bytes
        const cipher = crypto.createCipheriv('aes-256-gcm', this.key, iv);
        
        if (associatedData) {
            cipher.setAAD(Buffer.from(associatedData, 'utf8'));
        }
        
        let encrypted = cipher.update(plaintext, 'utf8');
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        
        const tag = cipher.getAuthTag();
        
        return {
            iv: iv.toString('hex'),
            encrypted: encrypted.toString('hex'),
            tag: tag.toString('hex'),
            associatedData: associatedData
        };
    }
    
    decrypt(encryptedData) {
        const decipher = crypto.createDecipheriv(
            'aes-256-gcm', 
            this.key, 
            Buffer.from(encryptedData.iv, 'hex')
        );
        
        if (encryptedData.associatedData) {
            decipher.setAAD(Buffer.from(encryptedData.associatedData, 'utf8'));
        }
        
        decipher.setAuthTag(Buffer.from(encryptedData.tag, 'hex'));
        
        let decrypted = decipher.update(Buffer.from(encryptedData.encrypted, 'hex'));
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        
        return decrypted.toString('utf8');
    }
    
    encryptWithFixedIV(plaintext, iv, associatedData = null) {
        const cipher = crypto.createCipheriv('aes-256-gcm', this.key, iv);
        
        if (associatedData) {
            cipher.setAAD(Buffer.from(associatedData, 'utf8'));
        }
        
        let encrypted = cipher.update(plaintext, 'utf8');
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        
        const tag = cipher.getAuthTag();
        
        return {
            encrypted: encrypted.toString('hex'),
            tag: tag.toString('hex'),
            associatedData: associatedData
        };
    }
    
    decryptWithFixedIV(encryptedData, iv) {
        const decipher = crypto.createDecipheriv('aes-256-gcm', this.key, iv);
        
        if (encryptedData.associatedData) {
            decipher.setAAD(Buffer.from(encryptedData.associatedData, 'utf8'));
        }
        
        decipher.setAuthTag(Buffer.from(encryptedData.tag, 'hex'));
        
        let decrypted = decipher.update(Buffer.from(encryptedData.encrypted, 'hex'));
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        
        return decrypted.toString('utf8');
    }
}

// Example usage
function example() {
    console.log('===== Production-Ready AES-GCM Example =====');
    
    const aesGcm = new AESGCM('63f4945d921d599f27ae4fdf5bada3f1');
    const plaintext = 'This is a secret message encrypted with production-ready AES-GCM implementation.';
    
    console.log('Plaintext:', plaintext);
    
    // Test basic encryption/decryption
    console.log('\n--- Basic Encryption/Decryption ---');
    const encrypted = aesGcm.encrypt(plaintext);
    console.log('Encrypted:', encrypted.encrypted);
    console.log('IV:', encrypted.iv);
    console.log('Authentication Tag:', encrypted.tag);
    
    const decrypted = aesGcm.decrypt(encrypted);
    console.log('Decrypted:', decrypted);
    
    console.log('Encryption/Decryption successful:', plaintext === decrypted);
    
    // Test with associated data
    console.log('\n--- With Associated Data ---');
    const associatedData = 'user:12345;action:transfer;amount:1000';
    const encryptedWithAD = aesGcm.encrypt(plaintext, associatedData);
    console.log('Associated Data:', associatedData);
    console.log('Encrypted with AD:', encryptedWithAD.encrypted);
    
    const decryptedWithAD = aesGcm.decrypt(encryptedWithAD);
    console.log('Decrypted with AD:', decryptedWithAD);
    
    console.log('With AD successful:', plaintext === decryptedWithAD);
    
    // Test with tampered data (should fail)
    console.log('\n--- Tampered Data Test ---');
    const encryptedBuffer = Buffer.from(encrypted.encrypted, 'hex');
    const tamperedBuffer = Buffer.from(encryptedBuffer);
    tamperedBuffer[0] = tamperedBuffer[0] ^ 0x01;
    const tamperedData = {
        ...encrypted,
        encrypted: tamperedBuffer.toString('hex')
    };
    
    try {
        const tamperedDecrypted = aesGcm.decrypt(tamperedData);
        console.log('Tampered data decrypted (this should not happen):', tamperedDecrypted);
    } catch (error) {
        console.log('Tampered data correctly rejected:', error.message);
    }
    
    // Test with tampered associated data
    console.log('\n--- Tampered Associated Data Test ---');
    const tamperedAD = {
        ...encryptedWithAD,
        associatedData: 'user:12345;action:transfer;amount:9999' // Tampered amount
    };
    
    try {
        const tamperedADDecrypted = aesGcm.decrypt(tamperedAD);
        console.log('Data with tampered AD decrypted (this should not happen):', tamperedADDecrypted);
    } catch (error) {
        console.log('Data with tampered AD correctly rejected:', error.message);
    }
    
    // Test with fixed IV (for certain use cases)
    console.log('\n--- Fixed IV Example ---');
    const fixedIV = crypto.randomBytes(12);
    const message1 = 'First message with fixed IV';
    const message2 = 'Second message with fixed IV';
    
    const encrypted1 = aesGcm.encryptWithFixedIV(message1, fixedIV);
    const encrypted2 = aesGcm.encryptWithFixedIV(message2, fixedIV);
    
    console.log('Message 1:', message1);
    console.log('Message 2:', message2);
    console.log('Fixed IV:', fixedIV.toString('hex'));
    
    const decrypted1 = aesGcm.decryptWithFixedIV(encrypted1, fixedIV);
    const decrypted2 = aesGcm.decryptWithFixedIV(encrypted2, fixedIV);
    
    console.log('Decrypted 1:', decrypted1);
    console.log('Decrypted 2:', decrypted2);
    
    console.log('Fixed IV encryption successful:', 
               message1 === decrypted1 && message2 === decrypted2);
    
    // Performance comparison with AES-CBC
    console.log('\n--- Performance Comparison ---');
    const { AES } = require('../aes/aes.example');
    const aes = new AES('63f4945d921d599f27ae4fdf5bada3f1');
    
    const largeMessage = 'x'.repeat(10000);
    
    // Measure AES-GCM encryption time
    const gcmStart = process.hrtime.bigint();
    const gcmEncrypted = aesGcm.encrypt(largeMessage);
    const gcmEnd = process.hrtime.bigint();
    
    // Measure AES-CBC encryption time
    const cbcStart = process.hrtime.bigint();
    const cbcEncrypted = aes.encrypt(largeMessage);
    const cbcEnd = process.hrtime.bigint();
    
    const gcmTime = Number(gcmEnd - gcmStart) / 1000000; // Convert to milliseconds
    const cbcTime = Number(cbcEnd - cbcStart) / 1000000; // Convert to milliseconds
    
    console.log(`AES-GCM encryption time: ${gcmTime.toFixed(2)} ms`);
    console.log(`AES-CBC encryption time: ${cbcTime.toFixed(2)} ms`);
    console.log(`AES-GCM is ${cbcTime / gcmTime}x ${gcmTime < cbcTime ? 'faster' : 'slower'} than AES-CBC`);
}

if (require.main === module) {
    example();
}

module.exports = { AESGCM, example };