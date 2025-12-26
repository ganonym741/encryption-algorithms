/**
 * Diffie-Hellman Key Exchange Implementation
 * This is a simplified educational implementation of Diffie-Hellman key exchange protocol
 * Note: For production use, always use well-vetted cryptographic libraries like Node.js's built-in crypto module
 */

class DiffieHellman {
    // Create DiffieHellman with predefined group
    constructor(group) {
        if (typeof group === 'string') {
            // Using predefined group
            const groupParams = DiffieHellman.COMMON_GROUPS[group];
            this.p = groupParams.p;
            this.g = groupParams.g;
        } else {
            // Using custom parameters
            this.p = group.p;
            this.g = group.g;
        }
        
        // Generate private key (random number between 1 and p-1)
        this.privateKey = this.generatePrivateKey();
        
        // Calculate public key
        this.publicKey = this.modPow(this.g, this.privateKey, this.p);
    }

    // Generate a random private key
    generatePrivateKey() {
        // Generate a random number between 1 and p-1
        const bitLength = this.p.toString(2).length;
        let privateKey;
        
        do {
            privateKey = this.randomBigInt(1n, this.p - 1n);
        } while (privateKey <= 1n || privateKey >= this.p - 1n);
        
        return privateKey;
    }

    // Generate a random BigInt in range [min, max]
    randomBigInt(min, max) {
        const range = max - min + 1n;
        const bitsNeeded = range.toString(2).length;
        
        let result = 0n;
        for (let i = 0; i < bitsNeeded; i += 30) {
            // Generate 30 random bits at a time
            const randomValue = Math.floor(Math.random() * (1 << 30));
            result = (result << BigInt(30)) + BigInt(randomValue);
        }
        
        // Ensure result is in correct range
        result = result % range;
        return result + min;
    }

    // Modular exponentiation (base^exponent mod modulus)
    modPow(base, exponent, modulus) {
        if (modulus === 1n) return 0n;
        
        let result = 1n;
        let b = base % modulus;
        let e = exponent;
        
        while (e > 0n) {
            if (e % 2n === 1n) {
                result = (result * b) % modulus;
            }
            e >>= 1n;
            b = (b * b) % modulus;
        }
        
        return result;
    }

    // Get public key
    getPublicKey() {
        return this.publicKey;
    }

    // Get parameters (p, g)
    getParameters() {
        return { p: this.p, g: this.g };
    }

    // Compute shared secret using other party's public key
    computeSharedSecret(otherPublicKey) {
        // Verify that other public key is in correct range
        if (otherPublicKey <= 1n || otherPublicKey >= this.p - 1n) {
            throw new Error('Invalid public key');
        }
        
        // Compute shared secret: otherPublicKey^privateKey mod p
        return this.modPow(otherPublicKey, this.privateKey, this.p);
    }

    // Convert BigInt to hex string
    static bigIntToHex(value) {
        return value.toString(16);
    }

    // Convert hex string to BigInt
    static hexToBigInt(hex) {
        return BigInt('0x' + hex);
    }

    // Convert BigInt to Uint8Array
    static bigIntToBytes(value) {
        const hex = value.toString(16);
        
        // Ensure even length
        const paddedHex = hex.length % 2 === 0 ? hex : '0' + hex;
        
        const bytes = new Uint8Array(paddedHex.length / 2);
        
        for (let i = 0; i < paddedHex.length; i += 2) {
            bytes[i / 2] = parseInt(paddedHex.substr(i, 2), 16);
        }
        
        return bytes;
    }

    // Convert Uint8Array to BigInt
    static bytesToBigInt(bytes) {
        let result = 0n;
        
        for (let i = 0; i < bytes.length; i++) {
            result = (result << 8n) + BigInt(bytes[i]);
        }
        
        return result;
    }

    // Perform a full Diffie-Hellman key exchange
    static performKeyExchange() {
        // Create Alice's Diffie-Hellman instance
        const alice = new DiffieHellman('SMALL_TEST'); // Use small group for demonstration
        
        // Create Bob's Diffie-Hellman instance with same parameters
        const bobParams = alice.getParameters();
        const bob = new DiffieHellman(bobParams);
        
        // Exchange public keys
        const alicePublicKey = alice.getPublicKey();
        const bobPublicKey = bob.getPublicKey();
        
        // Compute shared secrets
        console.log('Alice public key: ', alicePublicKey);
        console.log('Bob public key: ', bobPublicKey);
        const aliceSecret = alice.computeSharedSecret(bobPublicKey);
        const bobSecret = bob.computeSharedSecret(alicePublicKey);
        
        return {
            aliceSecret,
            bobSecret,
            secretsMatch: aliceSecret === bobSecret,
            alice,
            bob
        };
    }

    // Perform a man-in-the-middle attack demonstration
    static demonstrateMITMAttack() {
        // Create Alice and Bob's Diffie-Hellman instances
        const alice = new DiffieHellman('SMALL_TEST');
        const bob = new DiffieHellman('SMALL_TEST');
        
        // Create Mallory's (attacker) Diffie-Hellman instances
        const aliceParams = alice.getParameters();
        const malloryForAlice = new DiffieHellman(aliceParams);
        const malloryForBob = new DiffieHellman(aliceParams);
        
        // Exchange public keys (with Mallory intercepting and replacing them)
        const alicePublicKey = alice.getPublicKey();
        const bobPublicKey = bob.getPublicKey();
        const malloryForAlicePublicKey = malloryForAlice.getPublicKey();
        const malloryForBobPublicKey = malloryForBob.getPublicKey();
        
        // Mallory gives Alice her public key instead of Bob's
        // Mallory gives Bob her public key instead of Alice's
        
        // Compute shared secrets
        const aliceSecret = alice.computeSharedSecret(malloryForAlicePublicKey); // Alice thinks she's talking to Bob
        const bobSecret = bob.computeSharedSecret(malloryForBobPublicKey); // Bob thinks he's talking to Alice
        const mitmSecretForAlice = malloryForAlice.computeSharedSecret(alicePublicKey); // Mallory's secret with Alice
        const mitmSecretForBob = malloryForBob.computeSharedSecret(bobPublicKey); // Mallory's secret with Bob
        
        return {
            aliceSecret,
            bobSecret,
            mitmSecretForAlice,
            mitmSecretForBob,
            aliceThinksSheIsTalkingTo: "Bob (actually Mallory)",
            bobThinksHeIsTalkingTo: "Alice (actually Mallory)"
        };
    }
}

// Commonly used prime and generator values
DiffieHellman.COMMON_GROUPS = {
    // 2048-bit MODP Group (RFC 3526)
    MODP_2048: {
        p: BigInt("0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF"),
        g: 2n
    },
    // 1024-bit MODP Group (RFC 2409)
    MODP_1024: {
        p: BigInt("0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"),
        g: 2n
    },
    // Small group for testing (not secure for production)
    SMALL_TEST: {
        p: 23n,
        g: 5n
    }
};

// Example usage
function example() {
    console.log('--- Diffie-Hellman Key Exchange Example ---');
    
    // Perform a full key exchange
    const keyExchange = DiffieHellman.performKeyExchange();
    
    console.log('Alice\'s public key:', DiffieHellman.bigIntToHex(keyExchange.alice.getPublicKey()));
    console.log('Bob\'s public key:', DiffieHellman.bigIntToHex(keyExchange.bob.getPublicKey()));
    console.log('Alice\'s shared secret:', DiffieHellman.bigIntToHex(keyExchange.aliceSecret));
    console.log('Bob\'s shared secret:', DiffieHellman.bigIntToHex(keyExchange.bobSecret));
    console.log('Secrets match:', keyExchange.secretsMatch);
    
    // Demonstrate man-in-the-middle attack
    console.log('\n--- Man-in-the-Middle Attack Demonstration ---');
    const mitmAttack = DiffieHellman.demonstrateMITMAttack();
    
    console.log('Alice\'s shared secret:', DiffieHellman.bigIntToHex(mitmAttack.aliceSecret));
    console.log('Bob\'s shared secret:', DiffieHellman.bigIntToHex(mitmAttack.bobSecret));
    console.log('Mallory\'s secret with Alice:', DiffieHellman.bigIntToHex(mitmAttack.mitmSecretForAlice));
    console.log('Mallory\'s secret with Bob:', DiffieHellman.bigIntToHex(mitmAttack.mitmSecretForBob));
    console.log('Alice thinks she is talking to:', mitmAttack.aliceThinksSheIsTalkingTo);
    console.log('Bob thinks he is talking to:', mitmAttack.bobThinksHeIsTalkingTo);
    console.log('Alice and Bob have different secrets:', mitmAttack.aliceSecret !== mitmAttack.bobSecret);
    console.log('Mallory can decrypt messages from both parties:', 
        mitmAttack.aliceSecret === mitmAttack.mitmSecretForAlice && 
        mitmAttack.bobSecret === mitmAttack.mitmSecretForBob);
    
    // Demonstrate with larger group (more secure)
    console.log('\n--- Using 1024-bit MODP Group ---');
    const alice = new DiffieHellman('MODP_1024');
    const bobParams = alice.getParameters();
    const bob = new DiffieHellman(bobParams);
    
    const aliceSecret = alice.computeSharedSecret(bob.getPublicKey());
    const bobSecret = bob.computeSharedSecret(alice.getPublicKey());
    
    console.log('Alice\'s public key (1024-bit):', DiffieHellman.bigIntToHex(alice.getPublicKey()).substring(0, 20) + '...');
    console.log('Bob\'s public key (1024-bit):', DiffieHellman.bigIntToHex(bob.getPublicKey()).substring(0, 20) + '...');
    console.log('Shared secrets match:', aliceSecret === bobSecret);
    
    // Convert shared secret to bytes for use as encryption key
    const sharedSecretBytes = DiffieHellman.bigIntToBytes(aliceSecret);
    console.log('Shared secret as bytes (first 16):', Array.from(sharedSecretBytes.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join(''));
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { DiffieHellman, example };
} else {
    window.DiffieHellman = DiffieHellman;
    window.example = example;
}

// Note: To run the example, uncomment the line below or import and call example() from another file
// example();