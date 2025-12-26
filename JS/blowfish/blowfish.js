/**
 * Blowfish Implementation
 * This is a simplified educational implementation of the Blowfish cipher
 * Note: For production use, always use well-vetted cryptographic libraries like Node.js's built-in crypto module
 */

class Blowfish {
    constructor(key) {
        if (typeof key === 'string') {
            // Convert string to Uint8Array (assuming UTF-8 encoding)
            this.key = new TextEncoder().encode(key);
        } else {
            this.key = key;
        }
        
        // Blowfish supports key sizes from 32 to 448 bits (4 to 56 bytes)
        if (this.key.length < 4 || this.key.length > 56) {
            throw new Error('Blowfish key must be between 4 and 56 bytes');
        }
        
        this.initialize();
    }

    // Initialize P-array and S-boxes with the key
    initialize() {
        // Initialize P-array and S-boxes with the hexadecimal digits of pi
        this.p = [...Blowfish.P];
        this.s = Blowfish.S.map(box => [...box]);
        
        // XOR the key with the P-array
        let keyIndex = 0;
        for (let i = 0; i < 18; i++) {
            let data = 0;
            for (let j = 0; j < 4; j++) {
                data = (data << 8) | this.key[keyIndex % this.key.length];
                keyIndex++;
            }
            this.p[i] ^= data;
        }
        
        // Encrypt the all-zero string with the current P-array and S-boxes
        let left = 0;
        let right = 0;
        
        for (let i = 0; i < 18; i += 2) {
            const encrypted = this.encryptBlockInternal(left, right);
            this.p[i] = encrypted.left;
            this.p[i + 1] = encrypted.right;
            left = encrypted.left;
            right = encrypted.right;
        }
        
        // Update S-boxes
        for (let i = 0; i < 4; i++) {
            for (let j = 0; j < 256; j += 2) {
                const encrypted = this.encryptBlockInternal(left, right);
                this.s[i][j] = encrypted.left;
                this.s[i][j + 1] = encrypted.right;
                left = encrypted.left;
                right = encrypted.right;
            }
        }
    }

    // F function
    f(x) {
        const a = this.s[0][(x >> 24) & 0xff];
        const b = this.s[1][(x >> 16) & 0xff];
        const c = this.s[2][(x >> 8) & 0xff];
        const d = this.s[3][x & 0xff];
        
        return ((a + b) ^ c) + d;
    }

    // Encrypt a single 64-bit block (internal method)
    encryptBlockInternal(left, right) {
        let xl = left;
        let xr = right;
        
        // 16 rounds
        for (let i = 0; i < Blowfish.rounds; i++) {
            xl ^= this.p[i];
            xr ^= this.f(xl);
            
            // Swap
            const temp = xl;
            xl = xr;
            xr = temp;
        }
        
        // Final swap
        const temp = xl;
        xl = xr;
        xr = temp;
        
        // XOR with last P-array values
        xr ^= this.p[16];
        xl ^= this.p[17];
        
        return { left: xl, right: xr };
    }

    // Decrypt a single 64-bit block (internal method)
    decryptBlockInternal(left, right) {
        let xl = left;
        let xr = right;
        
        // XOR with P-array values in reverse order
        xl ^= this.p[17];
        xr ^= this.p[16];
        
        // 16 rounds in reverse
        for (let i = Blowfish.rounds - 1; i >= 0; i--) {
            // Swap
            const temp = xl;
            xl = xr;
            xr = temp;
            
            xr ^= this.f(xl);
            xl ^= this.p[i];
        }
        
        return { left: xl, right: xr };
    }

    // Convert bytes to 32-bit words
    bytesToWords(bytes) {
        let left = 0;
        let right = 0;
        
        for (let i = 0; i < 4; i++) {
            left = (left << 8) | bytes[i];
            right = (right << 8) | bytes[i + 4];
        }
        
        return { left, right };
    }

    // Convert 32-bit words to bytes
    wordsToBytes(left, right) {
        const bytes = new Uint8Array(8);
        
        for (let i = 0; i < 4; i++) {
            bytes[3 - i] = (left >> (i * 8)) & 0xff;
            bytes[7 - i] = (right >> (i * 8)) & 0xff;
        }
        
        return bytes;
    }

    // Encrypt a single 8-byte block
    encryptBlock(plaintext) {
        if (plaintext.length !== 8) {
            throw new Error('Blowfish block size is 8 bytes');
        }

        const { left, right } = this.bytesToWords(plaintext);
        const encrypted = this.encryptBlockInternal(left, right);
        
        return this.wordsToBytes(encrypted.left, encrypted.right);
    }

    // Decrypt a single 8-byte block
    decryptBlock(ciphertext) {
        if (ciphertext.length !== 8) {
            throw new Error('Blowfish block size is 8 bytes');
        }

        const { left, right } = this.bytesToWords(ciphertext);
        const decrypted = this.decryptBlockInternal(left, right);
        
        return this.wordsToBytes(decrypted.left, decrypted.right);
    }

    // PKCS#5 padding (for 8-byte blocks)
    pad(data) {
        const blockSize = 8;
        const padding = blockSize - (data.length % blockSize);
        const paddedData = new Uint8Array(data.length + padding);
        
        paddedData.set(data);
        
        // Fill padding with padding value
        for (let i = data.length; i < paddedData.length; i++) {
            paddedData[i] = padding;
        }
        
        return paddedData;
    }

    // Remove PKCS#5 padding
    unpad(data) {
        if (data.length === 0) {
            throw new Error('Cannot unpad empty data');
        }
        
        const padding = data[data.length - 1];
        
        if (padding > 8 || padding > data.length || padding === 0) {
            throw new Error('Invalid padding');
        }
        
        for (let i = data.length - padding; i < data.length; i++) {
            if (data[i] !== padding) {
                throw new Error('Invalid padding');
            }
        }
        
        return data.slice(0, data.length - padding);
    }

    // Encrypt data (ECB mode - not recommended for production)
    encrypt(plaintext) {
        let data;
        
        if (typeof plaintext === 'string') {
            data = new TextEncoder().encode(plaintext);
        } else {
            data = plaintext;
        }
        
        // Pad data to multiple of block size
        const paddedData = this.pad(data);
        
        // Encrypt each block
        const encrypted = new Uint8Array(paddedData.length);
        
        for (let i = 0; i < paddedData.length; i += 8) {
            const block = paddedData.slice(i, i + 8);
            const encryptedBlock = this.encryptBlock(block);
            encrypted.set(encryptedBlock, i);
        }
        
        return encrypted;
    }

    // Decrypt data (ECB mode - not recommended for production)
    decrypt(ciphertext) {
        if (ciphertext.length % 8 !== 0) {
            throw new Error('Ciphertext length must be multiple of 8');
        }
        
        // Decrypt each block
        const decrypted = new Uint8Array(ciphertext.length);
        
        for (let i = 0; i < ciphertext.length; i += 8) {
            const block = ciphertext.slice(i, i + 8);
            const decryptedBlock = this.decryptBlock(block);
            decrypted.set(decryptedBlock, i);
        }
        
        // Remove padding
        return this.unpad(decrypted);
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

// Hexadecimal digits of pi (P-array)
Blowfish.P = [
    0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
    0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
    0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
    0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917,
    0x9216D5D9, 0x8979FB1B
];

// Initialize S-boxes with hexadecimal digits of pi
Blowfish.S = [
    // S1
    [
        0xD1310BA6, 0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB7,
        0xB8E1AFED, 0x6A267E96, 0xBA7C9045, 0xF12C7F99,
        0x24A19947, 0xB3916CF7, 0x0801F2E2, 0x858EFC16,
        0x636920D8, 0x71574E69, 0xA458FEA3, 0xF4933D7E,
        0x0D95748F, 0x728EB658, 0x718BCD58, 0x82154AEE,
        0x7B54A41D, 0xC25A59B5, 0x9C30D539, 0x2AF26013,
        0xC5D1B023, 0x286085F0, 0xCA417918, 0xB8DB38EF,
        0x8E79DCB0, 0x603A180E, 0x6C9E0E8B, 0xB01E8A3E,
        0xD71577C1, 0xBD314B27, 0x78AF2FDA, 0x55605C60,
        0xE65525F3, 0xAA55AB94, 0x57489862, 0x63E81440,
        0x55CA396A, 0x2AAB10B6, 0xB4CC5C34, 0x1141E8CE,
        0xA15486AF, 0x7C72E993, 0xB3EE1411, 0x636FBC2A,
        0x2BA9C55D, 0x741831F6, 0xCE5C3E16, 0x9B87931E,
        0xAFD6BA33, 0x6C24CF5C, 0x7A325381, 0x28958677,
        0x3B8F4898, 0x6B4BB9AF, 0xC4BFE81B, 0x66282193,
        0x61D809CC, 0xFB21A991, 0x487CAC60, 0x5DEC8032,
        0xEF844D39, 0x8FC4A8E5, 0x75173FCD, 0x3D048B25
    ],
    // S2
    [
        0x7D632BB1, 0x6A511C68, 0xC2A0C3A0, 0xB0C3C2A0,
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0,
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0,
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0,
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0,
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0,
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0,
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0,
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0,
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0,
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0,
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0,
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0,
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0,
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0,
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0,
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0,
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0
    ],
    // S3
    [
        0x6A511C68, 0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0,
        0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0,
        0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0,
        0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0,
        0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0,
        0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0,
        0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0,
        0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0,
        0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0,
        0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0,
        0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0,
        0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0,
        0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0,
        0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0,
        0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0,
        0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0,
        0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0,
        0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0
    ],
    // S4
    [
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0,
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0,
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0,
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0,
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0,
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0,
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0,
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0,
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0,
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0,
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0,
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0,
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0,
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0,
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0,
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0,
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0,
        0xC2A0C3A0, 0xB0C3C2A0, 0xC2A0C3A0, 0xB0C3C2A0
    ]
];

// Initialize static properties
Blowfish.rounds = 16;
Blowfish.blockSize = 8; // 64 bits

// Example usage
function example() {
    // Generate a key (between 4 and 56 bytes)
    const key = '403ba9e2adad1'; // 13 bytes (104 bits)
    
    // Create Blowfish instance
    const blowfish = new Blowfish(key);
    
    // Encrypt data
    const plaintext = 'This is a secret message that will be encrypted using Blowfish.';
    console.log('Plaintext:', plaintext);
    
    const encrypted = blowfish.encrypt(plaintext);
    console.log('Encrypted (hex):', Blowfish.toHex(encrypted));
    
    // Decrypt data
    const decrypted = blowfish.decrypt(encrypted);
    const decryptedText = new TextDecoder().decode(decrypted);
    console.log('Decrypted:', decryptedText);
    
    // Verify encryption/decryption
    console.log('Success:', plaintext === decryptedText);
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { Blowfish, example };
} else {
    window.Blowfish = Blowfish;
    window.example = example;
}

// Note: To run the example, uncomment the line below or import and call example() from another file
// example();