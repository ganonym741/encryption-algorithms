/**
 * AES-GCM (Advanced Encryption Standard - Galois/Counter Mode) Implementation
 * This is a simplified educational implementation of AES-GCM
 * Note: For production use, always use well-vetted cryptographic libraries like Node.js's built-in crypto module
 */

// Import AES class
const { AES } = require('../aes/aes');

class AESGCM {
    constructor(key, iv) {
        // Set up the key (32 bytes for AES-256)
        if (typeof key === 'string') {
            this.key = new TextEncoder().encode(key);
        } else {
            this.key = key;
        }
        
        if (this.key.length !== 32) {
            throw new Error('AES-GCM key must be 32 bytes for AES-256');
        }
        
        // Set up the IV (12 bytes is recommended)
        if (typeof iv === 'string') {
            this.iv = new TextEncoder().encode(iv);
        } else {
            this.iv = iv;
        }
        
        if (this.iv.length !== 12) {
            throw new Error('AES-GCM IV must be 12 bytes');
        }
        
        this.aes = new AES(this.key);
    }

    // XOR two blocks
    xorBlock(a, b) {
        const result = new Uint8Array(AESGCM.BLOCK_SIZE);
        for (let i = 0; i < AESGCM.BLOCK_SIZE; i++) {
            result[i] = a[i] ^ b[i];
        }
        return result;
    }

    // Increment a block (treat as 128-bit big-endian integer)
    incrementBlock(block) {
        const result = new Uint8Array(block);
        let carry = 1;
        
        for (let i = result.length - 1; i >= 0 && carry > 0; i--) {
            const sum = result[i] + carry;
            result[i] = sum & 0xff;
            carry = sum >> 8;
        }
        
        return result;
    }

    // Galois Field multiplication (GF(2^128))
    gmul(a, b) {
        const result = new Uint8Array(AESGCM.BLOCK_SIZE).fill(0);
        
        for (let i = 0; i < AESGCM.BLOCK_SIZE; i++) {
            for (let j = 0; j < 8; j++) {
                if ((b[i] >> j) & 1) {
                    // XOR result with a shifted left by (8*i + j) bits
                    let temp = new Uint8Array(AESGCM.BLOCK_SIZE);
                    
                    // Copy a to temp
                    temp.set(a);
                    
                    // Shift left by (8*i + j) bits
                    const shiftBits = 8 * i + j;
                    const shiftBytes = Math.floor(shiftBits / 8);
                    const shiftRemainder = shiftBits % 8;
                    
                    if (shiftRemainder === 0) {
                        // Simple byte shift
                        for (let k = 0; k < AESGCM.BLOCK_SIZE - shiftBytes; k++) {
                            temp[k + shiftBytes] = temp[k];
                        }
                        for (let k = 0; k < shiftBytes; k++) {
                            temp[k] = 0;
                        }
                    } else {
                        // Complex shift with bit carry
                        for (let k = 0; k < AESGCM.BLOCK_SIZE - shiftBytes - 1; k++) {
                            temp[k + shiftBytes + 1] = (temp[k] << shiftRemainder) | (temp[k + 1] >> (8 - shiftRemainder));
                        }
                        temp[shiftBytes] = temp[0] << shiftRemainder;
                        for (let k = 0; k < shiftBytes; k++) {
                            temp[k] = 0;
                        }
                    }
                    
                    // XOR with result
                    for (let k = 0; k < AESGCM.BLOCK_SIZE; k++) {
                        result[k] ^= temp[k];
                    }
                }
            }
        }
        
        // Reduce using the irreducible polynomial x^128 + x^7 + x^2 + x + 1
        // This is a simplified reduction - in a real implementation, this would be more complex
        for (let i = 127; i >= 0; i--) {
            if ((result[Math.floor(i / 8)] >> (i % 8)) & 1) {
                // If the bit at position i is set, XOR with R shifted left by (i-127) bits
                const shift = i - 127;
                for (let j = 0; j < AESGCM.BLOCK_SIZE; j++) {
                    if (j + shift < AESGCM.BLOCK_SIZE) {
                        result[j + shift] ^= AESGCM.R[j];
                    }
                }
            }
        }
        
        return result;
    }

    // GHASH function for GCM
    ghash(h, a, c) {
        // Pad AAD (Additional Authenticated Data) to multiple of block size
        const paddedA = new Uint8Array(Math.ceil(a.length / AESGCM.BLOCK_SIZE) * AESGCM.BLOCK_SIZE);
        paddedA.set(a);
        
        // Pad ciphertext to multiple of block size
        const paddedC = new Uint8Array(Math.ceil(c.length / AESGCM.BLOCK_SIZE) * AESGCM.BLOCK_SIZE);
        paddedC.set(c);
        
        // Initialize Y0 to 0
        let y = new Uint8Array(AESGCM.BLOCK_SIZE).fill(0);
        
        // Process AAD blocks
        for (let i = 0; i < paddedA.length; i += AESGCM.BLOCK_SIZE) {
            const block = paddedA.slice(i, i + AESGCM.BLOCK_SIZE);
            y = new Uint8Array(this.xorBlock(y, block));
            y = new Uint8Array(this.gmul(y, h));
        }
        
        // Process ciphertext blocks
        for (let i = 0; i < paddedC.length; i += AESGCM.BLOCK_SIZE) {
            const block = paddedC.slice(i, i + AESGCM.BLOCK_SIZE);
            y = new Uint8Array(this.xorBlock(y, block));
            y = new Uint8Array(this.gmul(y, h));
        }
        
        // Process lengths (64-bit lengths of AAD and ciphertext)
        const lenBlock = new Uint8Array(AESGCM.BLOCK_SIZE);
        
        // Length of AAD in bits (64 bits, big-endian)
        const aLenBits = a.length * 8;
        for (let i = 0; i < 8; i++) {
            lenBlock[i] = (aLenBits >> (56 - i * 8)) & 0xff;
        }
        
        // Length of ciphertext in bits (64 bits, big-endian)
        const cLenBits = c.length * 8;
        for (let i = 0; i < 8; i++) {
            lenBlock[8 + i] = (cLenBits >> (56 - i * 8)) & 0xff;
        }
        
        y = new Uint8Array(this.xorBlock(y, lenBlock));
        y = new Uint8Array(this.gmul(y, h));
        
        return y;
    }

    // Generate the counter mode keystream
    generateCounterKeystream(length) {
        // Create the initial counter block (IV + 0x00000001)
        const counterBlock = new Uint8Array(AESGCM.BLOCK_SIZE);
        counterBlock.set(this.iv);
        counterBlock[AESGCM.BLOCK_SIZE - 1] = 1;
        
        const keystream = new Uint8Array(length);
        const blocksNeeded = Math.ceil(length / AESGCM.BLOCK_SIZE);
        
        for (let i = 0; i < blocksNeeded; i++) {
            // Encrypt the counter block
            // Create a new AES instance to access the encryptBlock method
            const tempAES = new AES(this.key);
            const encryptedCounter = tempAES.encryptBlock(counterBlock);
            
            // Copy to keystream
            const start = i * AESGCM.BLOCK_SIZE;
            const end = Math.min(start + AESGCM.BLOCK_SIZE, length);
            keystream.set(encryptedCounter.slice(0, end - start), start);
            
            // Increment the counter block
            this.incrementBlock(counterBlock);
        }
        
        return keystream;
    }

    // Encrypt data with AES-GCM
    encrypt(plaintext, aad) {
        let data;
        
        if (typeof plaintext === 'string') {
            data = new TextEncoder().encode(plaintext);
        } else {
            data = plaintext;
        }
        
        let additionalData;
        if (aad === undefined) {
            additionalData = new Uint8Array(0);
        } else if (typeof aad === 'string') {
            additionalData = new TextEncoder().encode(aad);
        } else {
            additionalData = aad;
        }
        
        // Generate H = Encrypt(0^128) for GHASH
        const zeroBlock = new Uint8Array(AESGCM.BLOCK_SIZE).fill(0);
        // Create a new AES instance to access the encryptBlock method
        const tempAES = new AES(this.key);
        const h = tempAES.encryptBlock(zeroBlock);
        
        // Generate the keystream for counter mode
        const keystream = this.generateCounterKeystream(data.length);
        
        // Encrypt the plaintext
        const ciphertext = new Uint8Array(data.length);
        for (let i = 0; i < data.length; i++) {
            ciphertext[i] = data[i] ^ keystream[i];
        }
        
        // Compute the authentication tag using GHASH
        const j0 = new Uint8Array(AESGCM.BLOCK_SIZE);
        j0.set(this.iv);
        j0[AESGCM.BLOCK_SIZE - 1] = 1;
        
        const s = this.ghash(h, additionalData, ciphertext);
        const encryptedJ0 = tempAES.encryptBlock(j0);
        const tag = this.xorBlock(s, encryptedJ0);
        
        return { ciphertext, tag };
    }

    // Decrypt data with AES-GCM
    decrypt(ciphertext, tag, aad) {
        let additionalData;
        if (aad === undefined) {
            additionalData = new Uint8Array(0);
        } else if (typeof aad === 'string') {
            additionalData = new TextEncoder().encode(aad);
        } else {
            additionalData = aad;
        }
        
        // Generate H = Encrypt(0^128) for GHASH
        const zeroBlock = new Uint8Array(AESGCM.BLOCK_SIZE).fill(0);
        // Create a new AES instance to access the encryptBlock method
        const tempAES2 = new AES(this.key);
        const h = tempAES2.encryptBlock(zeroBlock);
        
        // Compute the expected authentication tag
        const j0 = new Uint8Array(AESGCM.BLOCK_SIZE);
        j0.set(this.iv);
        j0[AESGCM.BLOCK_SIZE - 1] = 1;
        
        const s = this.ghash(h, additionalData, ciphertext);
        const encryptedJ0 = tempAES2.encryptBlock(j0);
        const expectedTag = this.xorBlock(s, encryptedJ0);
        
        // Verify the tag
        let tagMatch = true;
        for (let i = 0; i < AESGCM.TAG_SIZE; i++) {
            if (tag[i] !== expectedTag[i]) {
                tagMatch = false;
                break;
            }
        }
        
        if (!tagMatch) {
            return null; // Authentication failed
        }
        
        // Generate the keystream for counter mode
        const keystream = this.generateCounterKeystream(ciphertext.length);
        
        // Decrypt the ciphertext
        const plaintext = new Uint8Array(ciphertext.length);
        for (let i = 0; i < ciphertext.length; i++) {
            plaintext[i] = ciphertext[i] ^ keystream[i];
        }
        
        return plaintext;
    }

    // Convert Uint8Array to hex string
    static toHex(data) {
        return Array.from(data)
            .map(byte => byte.toString(16).padStart(2, '0'))
            .join('');
    }

    // Convert hex string to Uint8Array
    static fromHex(hex) {
        if (hex.length % 2 !== 0) {
            throw new Error('Hex string must have even length');
        }
        
        const bytes = new Uint8Array(hex.length / 2);
        
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        
        return bytes;
    }
}

// Constants for GHASH
AESGCM.R = new Uint8Array([
    0xe1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
]);

// Initialize static properties
AESGCM.BLOCK_SIZE = 16; // 16 bytes
AESGCM.TAG_SIZE = 16; // 16 bytes for authentication tag

// Example usage
function example() {
    // Generate a 32-byte key and 12-byte IV
    const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
    const iv = '69f71e2ae0c1'; // 12 bytes
    
    // Create AES-GCM instance
    const aesGcm = new AESGCM(key, iv);
    
    // Encrypt data with AAD
    const plaintext = 'This is a secret message that will be encrypted using AES-GCM.';
    const aad = 'Additional authenticated data';
    
    console.log('Plaintext:', plaintext);
    console.log('AAD:', aad);
    
    const { ciphertext, tag } = aesGcm.encrypt(plaintext, aad);
    console.log('Ciphertext (hex):', AESGCM.toHex(ciphertext));
    console.log('Authentication tag (hex):', AESGCM.toHex(tag));
    
    // Decrypt data with AAD
    const decrypted = aesGcm.decrypt(ciphertext, tag, aad);
    const decryptedText = decrypted ? new TextDecoder().decode(decrypted) : 'Decryption failed';
    console.log('Decrypted:', decryptedText);
    
    // Verify encryption/decryption
    console.log('Success:', plaintext === decryptedText);
    
    // Test with wrong AAD (should fail)
    console.log('\n--- Testing with wrong AAD ---');
    const wrongAad = 'Wrong additional data';
    const decryptedWithWrongAad = aesGcm.decrypt(ciphertext, tag, wrongAad);
    console.log('Decryption with wrong AAD:', decryptedWithWrongAad ? 'Failed - should be null' : 'Success - authentication failed as expected');
    
    // Test with wrong tag (should fail)
    console.log('\n--- Testing with wrong tag ---');
    const wrongTag = new Uint8Array(tag);
    wrongTag[0] ^= 0x01; // Flip one bit
    const decryptedWithWrongTag = aesGcm.decrypt(ciphertext, wrongTag, aad);
    console.log('Decryption with wrong tag:', decryptedWithWrongTag ? 'Failed - should be null' : 'Success - authentication failed as expected');
    
    // Test with modified ciphertext (should fail)
    console.log('\n--- Testing with modified ciphertext ---');
    const modifiedCiphertext = new Uint8Array(ciphertext);
    if (modifiedCiphertext.length > 0) {
        modifiedCiphertext[0] ^= 0x01; // Flip one bit
    }
    const decryptedWithModifiedCiphertext = aesGcm.decrypt(modifiedCiphertext, tag, aad);
    console.log('Decryption with modified ciphertext:', decryptedWithModifiedCiphertext ? 'Failed - should be null' : 'Success - authentication failed as expected');
    
    // Test with no AAD
    console.log('\n--- Testing with no AAD ---');
    const plaintextNoAAD = 'This is a message without additional authenticated data.';
    const { ciphertext: ciphertextNoAAD, tag: tagNoAAD } = aesGcm.encrypt(plaintextNoAAD);
    console.log('Ciphertext (hex):', AESGCM.toHex(ciphertextNoAAD));
    console.log('Authentication tag (hex):', AESGCM.toHex(tagNoAAD));
    
    const decryptedNoAAD = aesGcm.decrypt(ciphertextNoAAD, tagNoAAD);
    const decryptedTextNoAAD = decryptedNoAAD ? new TextDecoder().decode(decryptedNoAAD) : 'Decryption failed';
    console.log('Decrypted:', decryptedTextNoAAD);
    console.log('Success:', plaintextNoAAD === decryptedTextNoAAD);
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { AESGCM, example };
} else {
    window.AESGCM = AESGCM;
    window.example = example;
}

// Note: To run the example, uncomment the line below or import and call example() from another file
// example();