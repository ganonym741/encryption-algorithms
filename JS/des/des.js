/**
 * DES (Data Encryption Standard) and 3DES (Triple DES) Implementation
 * This is a simplified educational implementation
 * Note: For production use, always use well-vetted cryptographic libraries like Node.js's built-in crypto module
 */

class DES {
    constructor(key) {
        if (typeof key === 'string') {
            // Convert string to Uint8Array (assuming UTF-8 encoding)
            this.key = new TextEncoder().encode(key);
        } else {
            this.key = key;
        }
        
        // Ensure key is 8 bytes (64 bits) for DES
        if (this.key.length !== 8) {
            throw new Error('DES requires an 8-byte key');
        }
        
        this.subKeys = [];
        this.generateSubKeys();
    }

    // Convert bytes to bits
    bytesToBits(bytes) {
        const bits = [];
        for (let i = 0; i < bytes.length; i++) {
            for (let j = 7; j >= 0; j--) {
                bits.push((bytes[i] >> j) & 1);
            }
        }
        return bits;
    }

    // Convert bits to bytes
    bitsToBytes(bits) {
        const bytes = new Uint8Array(Math.ceil(bits.length / 8));
        for (let i = 0; i < bits.length; i++) {
            bytes[Math.floor(i / 8)] |= (bits[i] << (7 - (i % 8)));
        }
        return bytes;
    }

    // Permute bits according to a permutation table
    permute(bits, table) {
        const result = [];
        for (let i = 0; i < table.length; i++) {
            result.push(bits[table[i] - 1]);
        }
        return result;
    }

    // Left circular shift
    leftShift(bits, shifts) {
        const n = bits.length;
        const result = [];
        for (let i = 0; i < n; i++) {
            result.push(bits[(i + shifts) % n]);
        }
        return result;
    }

    // Generate 16 subkeys
    generateSubKeys() {
        const keyBits = this.bytesToBits(this.key);
        
        // Apply PC-1
        const permutedKey = this.permute(keyBits, DES.PC1);
        
        // Split into C and D halves (28 bits each)
        const c = permutedKey.slice(0, 28);
        const d = permutedKey.slice(28);
        
        // Generate 16 subkeys
        for (let round = 0; round < DES.rounds; round++) {
            // Left shift C and D
            const shiftedC = this.leftShift(c, DES.leftShifts[round]);
            const shiftedD = this.leftShift(d, DES.leftShifts[round]);
            
            // Combine C and D
            const cd = [...shiftedC, ...shiftedD];
            
            // Apply PC-2 to get subkey
            const subKey = this.permute(cd, DES.PC2);
            this.subKeys.push(subKey);
        }
    }

    // F function
    f(right, key) {
        // Expand right half from 32 to 48 bits
        const expanded = this.permute(right, DES.E);
        
        // XOR with key
        const xored = [];
        for (let i = 0; i < 48; i++) {
            xored.push(expanded[i] ^ key[i]);
        }
        
        // Apply S-boxes
        const sBoxOutput = [];
        for (let i = 0; i < 8; i++) {
            const start = i * 6;
            const end = start + 6;
            const bits = xored.slice(start, end);
            
            // Get row and column for S-box lookup
            const row = (bits[0] << 1) | bits[5];
            const col = (bits[1] << 3) | (bits[2] << 2) | (bits[3] << 1) | bits[4];
            
            // Look up value in S-box
            const sValue = DES.S[i][row][col];
            
            // Convert to 4-bit binary
            for (let j = 3; j >= 0; j--) {
                sBoxOutput.push((sValue >> j) & 1);
            }
        }
        
        // Apply P permutation
        return this.permute(sBoxOutput, DES.P);
    }

    // Encrypt a single 8-byte block
    encryptBlock(plaintext) {
        if (plaintext.length !== 8) {
            throw new Error('DES block size is 8 bytes');
        }

        const blockBits = this.bytesToBits(plaintext);
        
        // Initial permutation
        const permuted = this.permute(blockBits, DES.IP);
        
        // Split into left and right halves (32 bits each)
        let left = permuted.slice(0, 32);
        let right = permuted.slice(32);
        
        // 16 rounds
        for (let round = 0; round < DES.rounds; round++) {
            const newRight = [];
            for (let i = 0; i < 32; i++) {
                newRight.push(left[i] ^ this.f(right, this.subKeys[round])[i]);
            }
            left = right;
            right = newRight;
        }
        
        // Combine right and left (reversed)
        const combined = [...right, ...left];
        
        // Final permutation
        const finalBits = this.permute(combined, DES.FP);
        
        return this.bitsToBytes(finalBits);
    }

    // Decrypt a single 8-byte block
    decryptBlock(ciphertext) {
        if (ciphertext.length !== 8) {
            throw new Error('DES block size is 8 bytes');
        }

        const blockBits = this.bytesToBits(ciphertext);
        
        // Initial permutation
        const permuted = this.permute(blockBits, DES.IP);
        
        // Split into left and right halves (32 bits each)
        let left = permuted.slice(0, 32);
        let right = permuted.slice(32);
        
        // 16 rounds (reverse order of subkeys)
        for (let round = DES.rounds - 1; round >= 0; round--) {
            const newRight = [];
            for (let i = 0; i < 32; i++) {
                newRight.push(left[i] ^ this.f(right, this.subKeys[round])[i]);
            }
            left = right;
            right = newRight;
        }
        
        // Combine right and left (reversed)
        const combined = [...right, ...left];
        
        // Final permutation
        const finalBits = this.permute(combined, DES.FP);
        
        return this.bitsToBytes(finalBits);
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
        
        if (padding > 8 || padding > data.length) {
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

class TripleDES {
    constructor(key1, key2, key3) {
        // If only one key is provided, use it for all three DES operations
        if (!key2) {
            key2 = key1;
        }
        if (!key3) {
            key3 = key1;
        }
        
        this.des1 = new DES(key1);
        this.des2 = new DES(key2);
        this.des3 = new DES(key3);
    }

    // Encrypt data using 3DES (EDE mode: Encrypt-Decrypt-Encrypt)
    encrypt(plaintext) {
        let data;
        
        if (typeof plaintext === 'string') {
            data = new TextEncoder().encode(plaintext);
        } else {
            data = plaintext;
        }
        
        // Step 1: Encrypt with key1
        const encrypted1 = this.des1.encrypt(data);
        
        // Step 2: Decrypt with key2
        const decrypted2 = this.des2.decrypt(encrypted1);
        
        // Step 3: Encrypt with key3
        const encrypted3 = this.des3.encrypt(decrypted2);
        
        return encrypted3;
    }

    // Decrypt data using 3DES (DED mode: Decrypt-Encrypt-Decrypt)
    decrypt(ciphertext) {
        // Step 1: Decrypt with key3
        const decrypted1 = this.des3.decrypt(ciphertext);
        
        // Step 2: Encrypt with key2
        const encrypted2 = this.des2.encrypt(decrypted1);
        
        // Step 3: Decrypt with key1
        const decrypted3 = this.des1.decrypt(encrypted2);
        
        return decrypted3;
    }

    // Convert Uint8Array to hex string
    static toHex(data) {
        return DES.toHex(data);
    }

    // Convert hex string to Uint8Array
    static fromHex(hex) {
        return DES.fromHex(hex);
    }
}

// Initialize static properties for DES
DES.rounds = 16;

// Initial permutation (IP) table
DES.IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
];

// Final permutation (FP) table (inverse of IP)
DES.FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
];

// Expansion permutation table (E-table)
DES.E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
];

// Permutation function (P-table)
DES.P = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
];

// S-boxes
DES.S = [
    // S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    // S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    // S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    // S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    // S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    // S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    // S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    // S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
];

// Permuted choice 1 (PC-1) table
DES.PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
];

// Permuted choice 2 (PC-2) table
DES.PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
];

// Left shifts for key schedule
DES.leftShifts = [
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
];

// Example usage
function example() {
    // Generate 8-byte keys for DES
    const desKey = 'bd5a5670'; // 8 bytes
    
    // Create DES instance
    const des = new DES(desKey);
    
    // Encrypt data
    const plaintext = 'This is a secret message that will be encrypted using DES.';
    console.log('Plaintext:', plaintext);
    
    const encrypted = des.encrypt(plaintext);
    console.log('Encrypted (hex):', DES.toHex(encrypted));
    
    // Decrypt data
    const decrypted = des.decrypt(encrypted);
    const decryptedText = new TextDecoder().decode(decrypted);
    console.log('Decrypted:', decryptedText);
    
    // Verify encryption/decryption
    console.log('DES Success:', plaintext === decryptedText);
    
    // 3DES example
    console.log('\n--- 3DES Example ---');
    
    // Generate 8-byte keys for 3DES
    const key1 = 'bd5a5670'; // 8 bytes
    const key2 = '109398ec'; // 8 bytes
    const key3 = '3130afae'; // 8 bytes
    
    // Create 3DES instance
    const tripleDes = new TripleDES(key1, key2, key3);
    
    // Encrypt data
    const plaintext3DES = 'This is a secret message that will be encrypted using Triple DES.';
    console.log('Plaintext:', plaintext3DES);
    
    const encrypted3DES = tripleDes.encrypt(plaintext3DES);
    console.log('Encrypted (hex):', TripleDES.toHex(encrypted3DES));
    
    // Decrypt data
    const decrypted3DES = tripleDes.decrypt(encrypted3DES);
    const decryptedText3DES = new TextDecoder().decode(decrypted3DES);
    console.log('Decrypted:', decryptedText3DES);
    
    // Verify encryption/decryption
    console.log('3DES Success:', plaintext3DES === decryptedText3DES);
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { DES, TripleDES, example };
} else {
    window.DES = DES;
    window.TripleDES = TripleDES;
    window.example = example;
}

// Note: To run the example, uncomment the line below or import and call example() from another file
// example();