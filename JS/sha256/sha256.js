/**
 * SHA-256 (Secure Hash Algorithm 256-bit) Implementation
 * This is a simplified educational implementation of SHA-256
 * Note: For production use, always use well-vetted cryptographic libraries like Node.js's built-in crypto module
 */

class SHA256 {
    // Convert a string to an array of 32-bit words
    static stringToWords(message) {
        const messageBytes = new TextEncoder().encode(message);
        const messageLength = messageBytes.length;
        
        // Calculate the number of 512-bit blocks needed
        const blocksNeeded = Math.ceil((messageLength + 9) / 64);
        const words = new Array(blocksNeeded * 16).fill(0);
        
        // Copy the message bytes into the word array
        for (let i = 0; i < messageLength; i++) {
            const wordIndex = Math.floor(i / 4);
            const byteIndex = i % 4;
            words[wordIndex] = (words[wordIndex] << 8) | messageBytes[i];
        }
        
        // Append the '1' bit
        const lastByteIndex = messageLength % 4;
        const lastWordIndex = Math.floor(messageLength / 4);
        
        if (lastByteIndex === 0) {
            words[lastWordIndex] = 0x80000000;
        } else {
            words[lastWordIndex] = (words[lastWordIndex] | (0x80 << (24 - lastByteIndex * 8))) >>> 0;
        }
        
        // Append the original message length in bits as a 64-bit integer
        const messageLengthBits = messageLength * 8;
        const lastTwoWordsIndex = words.length - 2;
        
        words[lastTwoWordsIndex] = Math.floor(messageLengthBits / 0x100000000);
        words[lastTwoWordsIndex + 1] = messageLengthBits % 0x100000000;
        
        return words;
    }

    // Process a 512-bit block
    static processBlock(words, start, hash) {
        // Create a message schedule
        const w = new Array(64);
        
        // Copy the first 16 words from the block
        for (let i = 0; i < 16; i++) {
            w[i] = words[start + i];
        }
        
        // Extend the first 16 words into the remaining 48 words
        for (let i = 16; i < 64; i++) {
            w[i] = (SHA256.gamma1(w[i - 2]) + w[i - 7] + SHA256.gamma0(w[i - 15]) + w[i - 16]) >>> 0;
        }
        
        // Initialize working variables with the current hash value
        let [a, b, c, d, e, f, g, h] = hash;
        
        // Compression loop
        for (let i = 0; i < 64; i++) {
            const t1 = (h + SHA256.sigma1(e) + SHA256.ch(e, f, g) + SHA256.K[i] + w[i]) >>> 0;
            const t2 = (SHA256.sigma0(a) + SHA256.maj(a, b, c)) >>> 0;
            
            h = g;
            g = f;
            f = e;
            e = (d + t1) >>> 0;
            d = c;
            c = b;
            b = a;
            a = (t1 + t2) >>> 0;
        }
        
        // Update hash value
        hash[0] = (hash[0] + a) >>> 0;
        hash[1] = (hash[1] + b) >>> 0;
        hash[2] = (hash[2] + c) >>> 0;
        hash[3] = (hash[3] + d) >>> 0;
        hash[4] = (hash[4] + e) >>> 0;
        hash[5] = (hash[5] + f) >>> 0;
        hash[6] = (hash[6] + g) >>> 0;
        hash[7] = (hash[7] + h) >>> 0;
    }

    // Compute the SHA-256 hash of a message
    static hash(message) {
        let words;
        
        if (typeof message === 'string') {
            words = SHA256.stringToWords(message);
        } else {
            // Convert Uint8Array to string first (simplified approach)
            const str = new TextDecoder().decode(message);
            words = SHA256.stringToWords(str);
        }
        
        // Initialize hash with the initial hash values
        const hash = [...SHA256.H];
        
        // Process each 512-bit block
        for (let i = 0; i < words.length; i += 16) {
            SHA256.processBlock(words, i, hash);
        }
        
        // Convert hash to a hexadecimal string
        return hash.map(h => h.toString(16).padStart(8, '0')).join('');
    }

    // Compute SHA-256 hash of a file (simplified for demonstration)
    static async hashFile(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            
            reader.onload = (event) => {
                try {
                    const arrayBuffer = event.target?.result;
                    const uint8Array = new Uint8Array(arrayBuffer);
                    const hash = SHA256.hash(uint8Array);
                    resolve(hash);
                } catch (error) {
                    reject(error);
                }
            };
            
            reader.onerror = () => {
                reject(new Error('Failed to read file'));
            };
            
            reader.readAsArrayBuffer(file);
        });
    }

    // Compute HMAC-SHA256 (Hash-based Message Authentication Code)
    static hmac(key, message) {
        let keyBytes;
        
        if (typeof key === 'string') {
            keyBytes = new TextEncoder().encode(key);
        } else {
            keyBytes = key;
        }
        
        let messageBytes;
        
        if (typeof message === 'string') {
            messageBytes = new TextEncoder().encode(message);
        } else {
            messageBytes = message;
        }
        
        // If the key is longer than the block size (64 bytes for SHA-256), hash it
        if (keyBytes.length > 64) {
            const keyHash = SHA256.hash(keyBytes);
            keyBytes = new Uint8Array(32);
            for (let i = 0; i < 32; i++) {
                keyBytes[i] = parseInt(keyHash.substr(i * 2, 2), 16);
            }
        }
        
        // If the key is shorter than the block size, pad it with zeros
        if (keyBytes.length < 64) {
            const paddedKey = new Uint8Array(64);
            paddedKey.set(keyBytes);
            keyBytes = paddedKey;
        }
        
        // Create the inner and outer pads
        const innerPad = new Uint8Array(64);
        const outerPad = new Uint8Array(64);
        
        for (let i = 0; i < 64; i++) {
            innerPad[i] = keyBytes[i] ^ 0x36;
            outerPad[i] = keyBytes[i] ^ 0x5c;
        }
        
        // Compute inner hash: hash(innerPad || message)
        const innerCombined = new Uint8Array(64 + messageBytes.length);
        innerCombined.set(innerPad);
        innerCombined.set(messageBytes, 64);
        
        const innerHash = SHA256.hash(innerCombined);
        
        // Convert inner hash to bytes
        const innerHashBytes = new Uint8Array(32);
        for (let i = 0; i < 32; i++) {
            innerHashBytes[i] = parseInt(innerHash.substr(i * 2, 2), 16);
        }
        
        // Compute outer hash: hash(outerPad || innerHash)
        const outerCombined = new Uint8Array(64 + 32);
        outerCombined.set(outerPad);
        outerCombined.set(innerHashBytes, 64);
        
        return SHA256.hash(outerCombined);
    }

    // Convert a hex string to a Uint8Array
    static hexToBytes(hex) {
        if (hex.length % 2 !== 0) {
            throw new Error('Hex string must have even length');
        }
        
        const bytes = new Uint8Array(hex.length / 2);
        
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        
        return bytes;
    }

    // Convert a Uint8Array to a hex string
    static bytesToHex(bytes) {
        return Array.from(bytes)
            .map(byte => byte.toString(16).padStart(2, '0'))
            .join('');
    }
}

// SHA-256 initial hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19)
SHA256.H = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
];

// SHA-256 round constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
SHA256.K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

// Right rotation
SHA256.rotr = (x, n) => {
    return ((x >>> n) | (x << (32 - n))) >>> 0;
};

// Right shift
SHA256.shr = (x, n) => {
    return x >>> n;
};

// SHA-256 logical functions
SHA256.ch = (x, y, z) => {
    return (x & y) ^ (~x & z);
};

SHA256.maj = (x, y, z) => {
    return (x & y) ^ (x & z) ^ (y & z);
};

SHA256.sigma0 = (x) => {
    return SHA256.rotr(x, 2) ^ SHA256.rotr(x, 13) ^ SHA256.rotr(x, 22);
};

SHA256.sigma1 = (x) => {
    return SHA256.rotr(x, 6) ^ SHA256.rotr(x, 11) ^ SHA256.rotr(x, 25);
};

SHA256.gamma0 = (x) => {
    return SHA256.rotr(x, 7) ^ SHA256.rotr(x, 18) ^ SHA256.shr(x, 3);
};

SHA256.gamma1 = (x) => {
    return SHA256.rotr(x, 17) ^ SHA256.rotr(x, 19) ^ SHA256.shr(x, 10);
};

// Example usage
function example() {
    // Hash a string
    const message = 'This is a test message for SHA-256 hashing.';
    console.log('Message:', message);
    
    const hash = SHA256.hash(message);
    console.log('SHA-256 Hash:', hash);
    
    // Verify the hash
    const hash2 = SHA256.hash(message);
    console.log('Hash verification:', hash === hash2);
    
    // Hash a Uint8Array
    const data = new Uint8Array([72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]); // "Hello World"
    const dataHash = SHA256.hash(data);
    console.log('Data Hash:', dataHash);
    
    // HMAC-SHA256 example
    const key = '63f4945d921d599f27ae4fdf5bada3f1';
    const hmacMessage = 'This is a message to authenticate';
    const hmac = SHA256.hmac(key, hmacMessage);
    console.log('HMAC-SHA256:', hmac);
    
    // Verify HMAC
    const hmac2 = SHA256.hmac(key, hmacMessage);
    console.log('HMAC verification:', hmac === hmac2);
    
    // Test with different key (should produce different HMAC)
    const hmac3 = SHA256.hmac('different-key', hmacMessage);
    console.log('HMAC with different key:', hmac3 !== hmac);
    
    // Test with different message (should produce different HMAC)
    const hmac4 = SHA256.hmac(key, 'different message');
    console.log('HMAC with different message:', hmac4 !== hmac);
    
    // Convert between hex and bytes
    const hashBytes = SHA256.hexToBytes(hash);
    const hashFromBytes = SHA256.bytesToHex(hashBytes);
    console.log('Hex to bytes and back:', hash === hashFromBytes);
    
    // Known test vectors (from NIST)
    console.log('\n--- Test Vectors ---');
    console.log('SHA-256(""):', SHA256.hash(''));
    console.log('Expected: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    
    console.log('SHA-256("abc"):', SHA256.hash('abc'));
    console.log('Expected: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    
    console.log('SHA-256("The quick brown fox jumps over the lazy dog"):', SHA256.hash('The quick brown fox jumps over the lazy dog'));
    console.log('Expected: d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb7620f65c7b6f1b76b1');
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { SHA256, example };
} else {
    window.SHA256 = SHA256;
    window.example = example;
}

// Note: To run the example, uncomment the line below or import and call example() from another file
// example();