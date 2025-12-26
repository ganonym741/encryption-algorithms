/**
 * ChaCha20 Implementation
 * This is a simplified educational implementation of ChaCha20 stream cipher
 * Note: For production use, always use well-vetted cryptographic libraries like Node.js's built-in crypto module
 */

class ChaCha20 {
    constructor(key, nonce, counter = 0) {
        // Set up key (32 bytes)
        if (typeof key === 'string') {
            this.key = new TextEncoder().encode(key);
        } else {
            this.key = key;
        }
        
        if (this.key.length !== 32) {
            throw new Error('ChaCha20 key must be 32 bytes');
        }
        
        // Set up nonce (12 bytes)
        if (typeof nonce === 'string') {
            this.nonce = new TextEncoder().encode(nonce);
        } else {
            this.nonce = nonce;
        }
        
        if (this.nonce.length !== 12) {
            throw new Error('ChaCha20 nonce must be 12 bytes');
        }
        
        this.counter = counter;
    }

    // Convert 4 bytes to a 32-bit little-endian integer
    bytesToWord(bytes, offset) {
        return (bytes[offset] & 0xff) |
               ((bytes[offset + 1] & 0xff) << 8) |
               ((bytes[offset + 2] & 0xff) << 16) |
               ((bytes[offset + 3] & 0xff) << 24);
    }

    // Convert a 32-bit integer to 4 little-endian bytes
    wordToBytes(word, bytes, offset) {
        bytes[offset] = word & 0xff;
        bytes[offset + 1] = (word >>> 8) & 0xff;
        bytes[offset + 2] = (word >>> 16) & 0xff;
        bytes[offset + 3] = (word >>> 24) & 0xff;
    }

    // Left rotation
    rotl(value, shift) {
        return ((value << shift) | (value >>> (32 - shift))) >>> 0;
    }

    // Quarter round function
    quarterRound(state, a, b, c, d) {
        state[a] = (state[a] + state[b]) >>> 0;
        state[d] = this.rotl(state[d] ^ state[a], 16);
        
        state[c] = (state[c] + state[d]) >>> 0;
        state[b] = this.rotl(state[b] ^ state[c], 12);
        
        state[a] = (state[a] + state[b]) >>> 0;
        state[d] = this.rotl(state[d] ^ state[a], 8);
        
        state[c] = (state[c] + state[d]) >>> 0;
        state[b] = this.rotl(state[b] ^ state[c], 7);
    }

    // Initialize ChaCha20 state
    initializeState(counter) {
        const state = new Array(ChaCha20.STATE_SIZE);
        
        // Constant (4 words)
        for (let i = 0; i < 4; i++) {
            state[i] = this.bytesToWord(new TextEncoder().encode(ChaCha20.CONSTANT), i * 4);
        }
        
        // Key (8 words)
        for (let i = 0; i < 8; i++) {
            state[4 + i] = this.bytesToWord(this.key, i * 4);
        }
        
        // Counter (1 word)
        state[12] = counter;
        
        // Nonce (3 words)
        for (let i = 0; i < 3; i++) {
            state[13 + i] = this.bytesToWord(this.nonce, i * 4);
        }
        
        return state;
    }

    // Generate a keystream block
    generateBlock(counter) {
        // Initialize state
        const state = this.initializeState(counter);
        const workingState = [...state];
        
        // Perform 20 rounds (10 double rounds)
        for (let round = 0; round < 10; round++) {
            // Column round
            this.quarterRound(workingState, 0, 4, 8, 12);
            this.quarterRound(workingState, 1, 5, 9, 13);
            this.quarterRound(workingState, 2, 6, 10, 14);
            this.quarterRound(workingState, 3, 7, 11, 15);
            
            // Diagonal round
            this.quarterRound(workingState, 0, 5, 10, 15);
            this.quarterRound(workingState, 1, 6, 11, 12);
            this.quarterRound(workingState, 2, 7, 8, 13);
            this.quarterRound(workingState, 3, 4, 9, 14);
        }
        
        // Add initial state to the working state
        for (let i = 0; i < ChaCha20.STATE_SIZE; i++) {
            workingState[i] = (workingState[i] + state[i]) >>> 0;
        }
        
        // Convert state to bytes
        const block = new Uint8Array(ChaCha20.BLOCK_SIZE);
        for (let i = 0; i < ChaCha20.STATE_SIZE; i++) {
            this.wordToBytes(workingState[i], block, i * 4);
        }
        
        return block;
    }

    // Generate keystream for given length
    generateKeystream(length) {
        const keystream = new Uint8Array(length);
        const blocksNeeded = Math.ceil(length / ChaCha20.BLOCK_SIZE);
        
        for (let i = 0; i < blocksNeeded; i++) {
            const block = this.generateBlock(this.counter + i);
            const start = i * ChaCha20.BLOCK_SIZE;
            const end = Math.min(start + ChaCha20.BLOCK_SIZE, length);
            
            keystream.set(block.slice(0, end - start), start);
        }
        
        return keystream;
    }

    // Encrypt or decrypt data (XOR with keystream)
    crypt(data) {
        let input;
        
        if (typeof data === 'string') {
            input = new TextEncoder().encode(data);
        } else {
            input = data;
        }
        
        const keystream = this.generateKeystream(input.length);
        const output = new Uint8Array(input.length);
        
        for (let i = 0; i < input.length; i++) {
            output[i] = input[i] ^ keystream[i];
        }
        
        return output;
    }

    // Encrypt data
    encrypt(plaintext) {
        return this.crypt(plaintext);
    }

    // Decrypt data
    decrypt(ciphertext) {
        return this.crypt(ciphertext);
    }

    // Get current counter
    getCounter() {
        return this.counter;
    }

    // Set the counter
    setCounter(counter) {
        this.counter = counter;
    }

    // Increment the counter
    incrementCounter() {
        this.counter++;
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

// Constants for ChaCha20
ChaCha20.CONSTANT = 'expand 32-byte k';
ChaCha20.ROUNDS = 20;
ChaCha20.BLOCK_SIZE = 64; // 64 bytes per block
ChaCha20.STATE_SIZE = 16; // 16 32-bit words in state

// Example usage
function example() {
    // Generate a 32-byte key and 12-byte nonce
    const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
    const nonce = '69f71e2ae0c1'; // 12 bytes
    
    // Create ChaCha20 instance
    const chacha = new ChaCha20(key, nonce);
    
    // Encrypt data
    const plaintext = 'This is a secret message that will be encrypted using ChaCha20.';
    console.log('Plaintext:', plaintext);
    
    const encrypted = chacha.encrypt(plaintext);
    console.log('Encrypted (hex):', ChaCha20.toHex(encrypted));
    
    // Decrypt data
    const decrypted = chacha.decrypt(encrypted);
    const decryptedText = new TextDecoder().decode(decrypted);
    console.log('Decrypted:', decryptedText);
    
    // Verify encryption/decryption
    console.log('Success:', plaintext === decryptedText);
    
    // Test with different counters
    console.log('\n--- Testing with different counters ---');
    
    // Reset counter to 0
    chacha.setCounter(0);
    const encrypted1 = chacha.encrypt('Test message 1');
    
    // Increment counter and encrypt another message
    chacha.incrementCounter();
    const encrypted2 = chacha.encrypt('Test message 2');
    
    // Reset counter to 0 and decrypt first message
    chacha.setCounter(0);
    const decrypted1 = new TextDecoder().decode(chacha.decrypt(encrypted1));
    console.log('Decrypted message 1:', decrypted1);
    
    // Increment counter and decrypt second message
    chacha.incrementCounter();
    const decrypted2 = new TextDecoder().decode(chacha.decrypt(encrypted2));
    console.log('Decrypted message 2:', decrypted2);
    
    // Test with a large message (multiple blocks)
    console.log('\n--- Testing with a large message ---');
    
    // Create a large message (more than one block)
    const largeMessage = 'This is a much longer message that spans multiple ChaCha20 blocks. '.repeat(10);
    chacha.setCounter(0); // Reset counter
    const largeEncrypted = chacha.encrypt(largeMessage);
    const largeDecrypted = new TextDecoder().decode(chacha.decrypt(largeEncrypted));
    console.log('Large message encryption successful:', largeMessage === largeDecrypted);
    
    // Test with binary data
    console.log('\n--- Testing with binary data ---');
    
    const binaryData = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC]);
    chacha.setCounter(0); // Reset counter
    const binaryEncrypted = chacha.encrypt(binaryData);
    const binaryDecrypted = chacha.decrypt(binaryEncrypted);
    
    let binaryMatch = true;
    for (let i = 0; i < binaryData.length; i++) {
        if (binaryData[i] !== binaryDecrypted[i]) {
            binaryMatch = false;
            break;
        }
    }
    console.log('Binary data encryption successful:', binaryMatch);
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { ChaCha20, example };
} else {
    window.ChaCha20 = ChaCha20;
    window.example = example;
}

// Note: To run the example, uncomment the line below or import and call example() from another file
// example();