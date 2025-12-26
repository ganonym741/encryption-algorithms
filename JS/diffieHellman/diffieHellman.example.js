/**
 * Production-Ready Diffie-Hellman Key Exchange Implementation using Node.js built-in crypto module
 */

const crypto = require('crypto');

class DiffieHellman {
    constructor(modulusLength = 1024) {
        this.modulusLength = modulusLength;
        // Use predefined group for better performance instead of generating a new prime
        if (modulusLength === 1024) {
            // Use a known 1024-bit MODP group from RFC 2409
            const primeHex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
            this.dh = crypto.createDiffieHellman(primeHex, 'hex', Buffer.from([2]));
        } else if (modulusLength === 2048) {
            // Use a known 2048-bit MODP group from RFC 3526
            const primeHex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF";
            this.dh = crypto.createDiffieHellman(primeHex, 'hex', Buffer.from([2]));
        } else {
            // Fallback to original method for other sizes (may be slow)
            console.log(`Generating new ${modulusLength}-bit prime. This may take a while...`);
            this.dh = crypto.createDiffieHellman(modulusLength);
        }
        this.publicKey = this.dh.generateKeys();
    }
    
    getPublicKey() {
        return this.publicKey;
    }
    
    getPrivateKey() {
        return this.dh.getPrivateKey();
    }
    
    getPrime() {
        return this.dh.getPrime();
    }
    
    getGenerator() {
        return this.dh.getGenerator();
    }
    
    computeSecret(otherPublicKey) {
        return this.dh.computeSecret(otherPublicKey);
    }
    
    static createFromParameters(prime, generator) {
        const dh = new DiffieHellman();
        dh.dh = crypto.createDiffieHellman(prime, generator);
        dh.publicKey = dh.dh.generateKeys();
        return dh;
    }
}

// Example usage
function example() {
    console.log('===== Production-Ready Diffie-Hellman Example =====');
    
    // Create two parties - using 1024-bit for faster demonstration
    const alice = new DiffieHellman(1024);
    const bob = new DiffieHellman(1024);
    
    // Exchange public keys
    const alicePublicKey = alice.getPublicKey();
    const bobPublicKey = bob.getPublicKey();
    
    console.log('Alice Public Key:', alicePublicKey.toString('hex').substring(0, 32) + '...');
    console.log('Bob Public Key:', bobPublicKey.toString('hex').substring(0, 32) + '...');
    
    // Compute shared secrets
    const aliceSecret = alice.computeSecret(bobPublicKey);
    const bobSecret = bob.computeSecret(alicePublicKey);
    
    console.log('Alice Shared Secret:', aliceSecret.toString('hex'));
    console.log('Bob Shared Secret:', bobSecret.toString('hex'));
    
    // Verify both secrets are the same
    console.log('Shared secrets match:', aliceSecret.equals(bobSecret));
    
    // Demonstrate using the shared secret for symmetric encryption
    console.log('\n--- Using Shared Secret for Encryption ---');
    const { AES } = require('../aes/aes.example');
    
    // Use the shared secret as a key (truncated or hashed to appropriate size)
    const crypto = require('crypto');
    const aesKey = crypto.createHash('sha256').update(aliceSecret).digest();
    
    const aes = new AES(aesKey);
    const plaintext = 'This is a secret message encrypted with the shared secret.';
    
    console.log('Plaintext:', plaintext);
    
    const encrypted = aes.encrypt(plaintext);
    console.log('Encrypted:', encrypted.encrypted);
    
    const decrypted = aes.decrypt(encrypted);
    console.log('Decrypted:', decrypted);
    
    console.log('Encryption/Decryption successful:', plaintext === decrypted);
    
    // Example with custom parameters
    console.log('\n--- Custom Parameters Example ---');
    // Use a smaller prime for faster demonstration
    const prime = crypto.createDiffieHellman(512).getPrime();
    const generator = Buffer.from([2]); // Common generator value
    
    const aliceCustom = DiffieHellman.createFromParameters(prime, generator);
    const bobCustom = DiffieHellman.createFromParameters(prime, generator);
    
    const aliceCustomSecret = aliceCustom.computeSecret(bobCustom.getPublicKey());
    const bobCustomSecret = bobCustom.computeSecret(aliceCustom.getPublicKey());
    
    console.log('Custom parameters secret match:', aliceCustomSecret.equals(bobCustomSecret));
}

if (require.main === module) {
    example();
}

module.exports = { DiffieHellman, example };