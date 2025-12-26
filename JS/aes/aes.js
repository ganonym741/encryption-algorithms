/**
 * AES (Advanced Encryption Standard) Implementation
 * This is a simplified educational implementation of AES-256
 * Note: For production use, always use well-vetted cryptographic libraries like Node.js's built-in crypto module
 */

class AES {
    constructor(key) {
        if (typeof key === 'string') {
            // Convert string to Uint8Array (assuming UTF-8 encoding)
            this.key = new TextEncoder().encode(key);
        } else {
            this.key = key;
        }
        
        // Ensure key is 32 bytes (256 bits) for AES-256
        if (this.key.length !== 32) {
            throw new Error('AES-256 requires a 32-byte key');
        }
    }

    // Key expansion
    keyExpansion() {
        const keyWords = [];
        
        // Convert key bytes to words (4 bytes each)
        for (let i = 0; i < this.key.length; i += 4) {
            keyWords.push(
                (this.key[i] << 24) |
                (this.key[i + 1] << 16) |
                (this.key[i + 2] << 8) |
                this.key[i + 3]
            );
        }

        const expandedKeyWords = [...keyWords];
        let i = keyWords.length;

        while (i < 4 * (this.rounds + 1)) {
            let temp = expandedKeyWords[i - 1];

            if (i % keyWords.length === 0) {
                // RotWord
                temp = ((temp << 8) & 0xffffff00) | ((temp >> 24) & 0xff);
                
                // SubWord
                temp = (AES.sBox[(temp >> 24) & 0xff] << 24) |
                       (AES.sBox[(temp >> 16) & 0xff] << 16) |
                       (AES.sBox[(temp >> 8) & 0xff] << 8) |
                       AES.sBox[temp & 0xff];
                
                // XOR with Rcon
                temp ^= AES.rCon[Math.floor(i / keyWords.length)] << 24;
            } else if (i % keyWords.length === 4) {
                // SubWord for AES-256
                temp = (AES.sBox[(temp >> 24) & 0xff] << 24) |
                       (AES.sBox[(temp >> 16) & 0xff] << 16) |
                       (AES.sBox[(temp >> 8) & 0xff] << 8) |
                       AES.sBox[temp & 0xff];
            }

            expandedKeyWords[i] = expandedKeyWords[i - keyWords.length] ^ temp;
            i++;
        }

        // Convert words back to bytes
        const roundKeys = [];
        for (let i = 0; i < expandedKeyWords.length; i += 4) {
            const roundKey = new Uint8Array(16);
            for (let j = 0; j < 4; j++) {
                const word = expandedKeyWords[i + j];
                roundKey[j * 4] = (word >> 24) & 0xff;
                roundKey[j * 4 + 1] = (word >> 16) & 0xff;
                roundKey[j * 4 + 2] = (word >> 8) & 0xff;
                roundKey[j * 4 + 3] = word & 0xff;
            }
            roundKeys.push(roundKey);
        }

        return roundKeys;
    }

    // SubBytes transformation
    subBytes(state) {
        for (let i = 0; i < 16; i++) {
            state[i] = AES.sBox[state[i]];
        }
    }

    // Inverse SubBytes transformation
    invSubBytes(state) {
        for (let i = 0; i < 16; i++) {
            state[i] = AES.invSBox[state[i]];
        }
    }

    // ShiftRows transformation
    shiftRows(state) {
        const temp = new Uint8Array(16);
        
        // Row 0: no shift
        temp[0] = state[0];
        temp[4] = state[4];
        temp[8] = state[8];
        temp[12] = state[12];
        
        // Row 1: shift left by 1
        temp[1] = state[5];
        temp[5] = state[9];
        temp[9] = state[13];
        temp[13] = state[1];
        
        // Row 2: shift left by 2
        temp[2] = state[10];
        temp[6] = state[14];
        temp[10] = state[2];
        temp[14] = state[6];
        
        // Row 3: shift left by 3
        temp[3] = state[15];
        temp[7] = state[3];
        temp[11] = state[7];
        temp[15] = state[11];
        
        // Copy back to state
        for (let i = 0; i < 16; i++) {
            state[i] = temp[i];
        }
    }

    // Inverse ShiftRows transformation
    invShiftRows(state) {
        const temp = new Uint8Array(16);
        
        // Row 0: no shift
        temp[0] = state[0];
        temp[4] = state[4];
        temp[8] = state[8];
        temp[12] = state[12];
        
        // Row 1: shift right by 1
        temp[1] = state[13];
        temp[5] = state[1];
        temp[9] = state[5];
        temp[13] = state[9];
        
        // Row 2: shift right by 2
        temp[2] = state[10];
        temp[6] = state[14];
        temp[10] = state[2];
        temp[14] = state[6];
        
        // Row 3: shift right by 3
        temp[3] = state[7];
        temp[7] = state[11];
        temp[11] = state[15];
        temp[15] = state[3];
        
        // Copy back to state
        for (let i = 0; i < 16; i++) {
            state[i] = temp[i];
        }
    }

    // Galois Field multiplication
    gmul(a, b) {
        let p = 0;
        let hiBitSet;
        
        for (let i = 0; i < 8; i++) {
            if ((b & 1) === 1) {
                p ^= a;
            }
            
            hiBitSet = (a & 0x80);
            a <<= 1;
            
            if (hiBitSet) {
                a ^= 0x1b; // x^8 + x^4 + x^3 + x + 1
            }
            
            b >>= 1;
        }
        
        return p % 256;
    }

    // MixColumns transformation
    mixColumns(state) {
        const temp = new Uint8Array(16);
        
        for (let i = 0; i < 4; i++) {
            const col = i * 4;
            temp[col] = this.gmul(0x02, state[col]) ^ this.gmul(0x03, state[col + 1]) ^ state[col + 2] ^ state[col + 3];
            temp[col + 1] = state[col] ^ this.gmul(0x02, state[col + 1]) ^ this.gmul(0x03, state[col + 2]) ^ state[col + 3];
            temp[col + 2] = state[col] ^ state[col + 1] ^ this.gmul(0x02, state[col + 2]) ^ this.gmul(0x03, state[col + 3]);
            temp[col + 3] = this.gmul(0x03, state[col]) ^ state[col + 1] ^ state[col + 2] ^ this.gmul(0x02, state[col + 3]);
        }
        
        // Copy back to state
        for (let i = 0; i < 16; i++) {
            state[i] = temp[i];
        }
    }

    // Inverse MixColumns transformation
    invMixColumns(state) {
        const temp = new Uint8Array(16);
        
        for (let i = 0; i < 4; i++) {
            const col = i * 4;
            temp[col] = this.gmul(0x0e, state[col]) ^ this.gmul(0x0b, state[col + 1]) ^ this.gmul(0x0d, state[col + 2]) ^ this.gmul(0x09, state[col + 3]);
            temp[col + 1] = this.gmul(0x09, state[col]) ^ this.gmul(0x0e, state[col + 1]) ^ this.gmul(0x0b, state[col + 2]) ^ this.gmul(0x0d, state[col + 3]);
            temp[col + 2] = this.gmul(0x0d, state[col]) ^ this.gmul(0x09, state[col + 1]) ^ this.gmul(0x0e, state[col + 2]) ^ this.gmul(0x0b, state[col + 3]);
            temp[col + 3] = this.gmul(0x0b, state[col]) ^ this.gmul(0x0d, state[col + 1]) ^ this.gmul(0x09, state[col + 2]) ^ this.gmul(0x0e, state[col + 3]);
        }
        
        // Copy back to state
        for (let i = 0; i < 16; i++) {
            state[i] = temp[i];
        }
    }

    // AddRoundKey transformation
    addRoundKey(state, roundKey) {
        for (let i = 0; i < 16; i++) {
            state[i] ^= roundKey[i];
        }
    }

    // Encrypt a single 16-byte block
    encryptBlock(plaintext) {
        if (plaintext.length !== 16) {
            throw new Error('AES block size is 16 bytes');
        }

        const state = new Uint8Array(plaintext);
        const roundKeys = this.keyExpansion();

        // Initial round
        this.addRoundKey(state, roundKeys[0]);

        // Main rounds
        for (let round = 1; round < this.rounds; round++) {
            this.subBytes(state);
            this.shiftRows(state);
            this.mixColumns(state);
            this.addRoundKey(state, roundKeys[round]);
        }

        // Final round (no MixColumns)
        this.subBytes(state);
        this.shiftRows(state);
        this.addRoundKey(state, roundKeys[this.rounds]);

        return state;
    }

    // Decrypt a single 16-byte block
    decryptBlock(ciphertext) {
        if (ciphertext.length !== 16) {
            throw new Error('AES block size is 16 bytes');
        }

        const state = new Uint8Array(ciphertext);
        const roundKeys = this.keyExpansion();

        // Initial round (inverse of final round)
        this.addRoundKey(state, roundKeys[this.rounds]);
        this.invShiftRows(state);
        this.invSubBytes(state);

        // Main rounds (in reverse)
        for (let round = this.rounds - 1; round > 0; round--) {
            this.addRoundKey(state, roundKeys[round]);
            this.invMixColumns(state);
            this.invShiftRows(state);
            this.invSubBytes(state);
        }

        // Final round (inverse of initial round)
        this.addRoundKey(state, roundKeys[0]);

        return state;
    }

    // PKCS#7 padding
    pad(data) {
        const blockSize = 16;
        const padding = blockSize - (data.length % blockSize);
        const paddedData = new Uint8Array(data.length + padding);
        
        paddedData.set(data);
        
        // Fill padding with padding value
        for (let i = data.length; i < paddedData.length; i++) {
            paddedData[i] = padding;
        }
        
        return paddedData;
    }

    // Remove PKCS#7 padding
    unpad(data) {
        if (data.length === 0) {
            throw new Error('Cannot unpad empty data');
        }
        
        const padding = data[data.length - 1];
        
        if (padding > 16 || padding > data.length) {
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
        
        for (let i = 0; i < paddedData.length; i += 16) {
            const block = paddedData.slice(i, i + 16);
            const encryptedBlock = this.encryptBlock(block);
            encrypted.set(encryptedBlock, i);
        }
        
        return encrypted;
    }

    // Decrypt data (ECB mode - not recommended for production)
    decrypt(ciphertext) {
        if (ciphertext.length % 16 !== 0) {
            throw new Error('Ciphertext length must be multiple of 16');
        }
        
        // Decrypt each block
        const decrypted = new Uint8Array(ciphertext.length);
        
        for (let i = 0; i < ciphertext.length; i += 16) {
            const block = ciphertext.slice(i, i + 16);
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

// AES S-box (substitution box)
AES.sBox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];

// AES Inverse S-box
AES.invSBox = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
];

// Round constants for key expansion
AES.rCon = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
];

// Initialize rounds property
AES.prototype.rounds = 14; // AES-256 uses 14 rounds

// Example usage
function example() {
    // Generate a 32-byte key (256 bits)
    const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
    
    // Create AES instance
    const aes = new AES(key);
    
    // Encrypt data
    const plaintext = 'This is a secret message that will be encrypted using AES-256.';
    console.log('Plaintext:', plaintext);
    
    const encrypted = aes.encrypt(plaintext);
    console.log('Encrypted (hex):', AES.toHex(encrypted));
    
    // Decrypt data
    const decrypted = aes.decrypt(encrypted);
    const decryptedText = new TextDecoder().decode(decrypted);
    console.log('Decrypted:', decryptedText);
    
    // Verify encryption/decryption
    console.log('Success:', plaintext === decryptedText);
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { AES, example };
} else {
    window.AES = AES;
    window.example = example;
}

// Note: To run the example, uncomment the line below or import and call example() from another file
// example();