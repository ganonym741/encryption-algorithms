/**
 * Production-Ready SHA-256 Implementation using Node.js built-in crypto module
 */

const crypto = require('crypto');

class SHA256 {
    hash(data) {
        const hash = crypto.createHash('sha256');
        hash.update(data);
        return hash.digest('hex');
    }
    
    hmac(data, key) {
        const hmac = crypto.createHmac('sha256', key);
        hmac.update(data);
        return hmac.digest('hex');
    }
    
    hashFile(filePath) {
        const fs = require('fs');
        const hash = crypto.createHash('sha256');
        const fileBuffer = fs.readFileSync(filePath);
        hash.update(fileBuffer);
        return hash.digest('hex');
    }
    
    compareHashes(hash1, hash2) {
        return crypto.timingSafeEqual(Buffer.from(hash1, 'hex'), Buffer.from(hash2, 'hex'));
    }
}

// Example usage
function example() {
    console.log('===== Production-Ready SHA-256 Example =====');
    
    const sha256 = new SHA256();
    const message = 'This is a message to be hashed with production-ready SHA-256 implementation.';
    
    console.log('Message:', message);
    
    const hash = sha256.hash(message);
    console.log('SHA-256 Hash:', hash);
    console.log('Hash length:', hash.length, 'characters');
    
    // Test HMAC
    console.log('\n--- HMAC Example ---');
    const secretKey = '63f4945d921d599f27ae4fdf5bada3f1';
    const hmac = sha256.hmac(message, secretKey);
    console.log('HMAC-SHA256:', hmac);
    
    // Test file hashing
    console.log('\n--- File Hashing Example ---');
    const fs = require('fs');
    const testFilePath = './test-file.txt';
    
    // Create a test file
    fs.writeFileSync(testFilePath, 'This is test content for file hashing.');
    
    const fileHash = sha256.hashFile(testFilePath);
    console.log('File SHA-256 Hash:', fileHash);
    
    // Clean up
    fs.unlinkSync(testFilePath);
    
    // Test hash comparison
    console.log('\n--- Hash Comparison Example ---');
    const hash1 = sha256.hash('test message');
    const hash2 = sha256.hash('test message');
    const hash3 = sha256.hash('different message');
    
    console.log('Hash 1:', hash1);
    console.log('Hash 2:', hash2);
    console.log('Hash 3:', hash3);
    
    console.log('Hash 1 equals Hash 2:', sha256.compareHashes(hash1, hash2));
    console.log('Hash 1 equals Hash 3:', sha256.compareHashes(hash1, hash3));
}

if (require.main === module) {
    example();
}

module.exports = { SHA256, example };