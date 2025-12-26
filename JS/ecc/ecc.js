/**
 * Elliptic Curve Cryptography (ECC) Implementation
 * This is a simplified educational implementation of ECC for educational purposes
 * Note: For production use, always use well-vetted cryptographic libraries like Node.js's built-in crypto module
 */

class ECC {
    constructor(privateKey) {
        if (privateKey === undefined) {
            // Generate a random private key
            this.privateKey = this.generatePrivateKey();
        } else {
            this.privateKey = privateKey;
        }
        
        // Calculate public key
        this.publicKey = this.scalarMultiply(this.privateKey, { x: ECC.Gx, y: ECC.Gy });
    }

    // Generate a random private key
    generatePrivateKey() {
        // Generate a random number between 1 and n-1
        const bitLength = ECC.n.toString(2).length;
        let privateKey;
        
        do {
            privateKey = this.randomBigInt(1n, ECC.n - 1n);
        } while (privateKey <= 1n || privateKey >= ECC.n - 1n);
        
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

    // Modular inverse using extended Euclidean algorithm
    modInverse(a, m) {
        // Extended Euclidean Algorithm
        let m0 = m;
        let y = 0n, x = 1n;
        
        if (m === 1n) return 0n;
        
        while (a > 1n) {
            // q is quotient
            const q = a / m;
            
            let t = m;
            
            // m is remainder now, process same as Euclid's algorithm
            m = a % m;
            a = t;
            t = y;
            
            // Update y and x
            y = x - q * y;
            x = t;
        }
        
        // Make x positive
        if (x < 0n) x += m0;
        
        return x;
    }

    // Point addition on elliptic curve
    pointAdd(p1, p2) {
        // Handle special cases
        if (p1.x === 0n && p1.y === 0n) return p2;
        if (p2.x === 0n && p2.y === 0n) return p1;
        
        // Check if points are negatives of each other
        if (p1.x === p2.x && p1.y === ECC.p - p2.y) {
            return { x: 0n, y: 0n }; // Point at infinity
        }
        
        let m;
        
        if (p1.x === p2.x && p1.y === p2.y) {
            // Point doubling
            m = (3n * p1.x * p1.x + ECC.a) * this.modInverse(2n * p1.y, ECC.p) % ECC.p;
        } else {
            // Point addition
            m = (p2.y - p1.y) * this.modInverse(p2.x - p1.x, ECC.p) % ECC.p;
        }
        
        // Ensure m is positive
        m = (m + ECC.p) % ECC.p;
        
        const x3 = (m * m - p1.x - p2.x) % ECC.p;
        const y3 = (m * (p1.x - x3) - p1.y) % ECC.p;
        
        // Ensure coordinates are positive
        return {
            x: (x3 + ECC.p) % ECC.p,
            y: (y3 + ECC.p) % ECC.p
        };
    }

    // Scalar multiplication (double-and-add algorithm)
    scalarMultiply(k, p) {
        let result = { x: 0n, y: 0n }; // Point at infinity
        let addend = p;
        
        while (k > 0n) {
            if (k % 2n === 1n) {
                result = this.pointAdd(result, addend);
            }
            
            addend = this.pointAdd(addend, addend);
            k >>= 1n;
        }
        
        return result;
    }

    // Get private key
    getPrivateKey() {
        return this.privateKey;
    }

    // Get public key
    getPublicKey() {
        return this.publicKey;
    }

    // Compress public key
    getCompressedPublicKey() {
        const prefix = this.publicKey.y % 2n === 0n ? 0x02 : 0x03;
        const xBytes = this.bigIntToBytes(this.publicKey.x, 32);
        const result = new Uint8Array(33);
        result[0] = prefix;
        result.set(xBytes, 1);
        return result;
    }

    // Convert BigInt to bytes
    bigIntToBytes(value, length) {
        const result = new Uint8Array(length);
        
        for (let i = length - 1; i >= 0; i--) {
            result[i] = Number(value & 0xffn);
            value >>= 8n;
        }
        
        return result;
    }

    // Convert bytes to BigInt
    bytesToBigInt(bytes) {
        let result = 0n;
        
        for (let i = 0; i < bytes.length; i++) {
            result = (result << 8n) + BigInt(bytes[i]);
        }
        
        return result;
    }

    // Sign a message using ECDSA
    sign(message) {
        let data;
        
        if (typeof message === 'string') {
            data = new TextEncoder().encode(message);
        } else {
            data = message;
        }
        
        // Hash message (simplified - in a real implementation, use SHA-256)
        let hash = 0n;
        for (let i = 0; i < data.length; i++) {
            hash = (hash * 31n + BigInt(data[i])) % ECC.n;
        }
        
        // Generate a random k
        let k;
        do {
            k = this.randomBigInt(1n, ECC.n - 1n);
        } while (k === 0n);
        
        // Calculate r and s
        const kG = this.scalarMultiply(k, { x: ECC.Gx, y: ECC.Gy });
        let r = kG.x % ECC.n;
        
        if (r === 0n) {
            return this.sign(message); // Try again with a different k
        }
        
        const kInv = this.modInverse(k, ECC.n);
        let s = (kInv * (hash + r * this.privateKey)) % ECC.n;
        
        if (s === 0n) {
            return this.sign(message); // Try again with a different k
        }
        
        // Apply low-S normalization to ensure s <= n/2
        if (s > ECC.n / 2n) {
            s = ECC.n - s;
        }
        
        return { r, s };
    }

    // Verify a signature using ECDSA
    verify(message, signature, publicKey) {
        let data;
        
        if (typeof message === 'string') {
            data = new TextEncoder().encode(message);
        } else {
            data = message;
        }
        
        // Check that r and s are in correct range
        if (signature.r < 1n || signature.r >= ECC.n || signature.s < 1n || signature.s >= ECC.n) {
            return false;
        }
        
        // Hash message (simplified - in a real implementation, use SHA-256)
        let hash = 0n;
        for (let i = 0; i < data.length; i++) {
            hash = (hash * 31n + BigInt(data[i])) % ECC.n;
        }
        
        // Calculate w, u1, and u2
        const w = this.modInverse(signature.s, ECC.n);
        const u1 = (hash * w) % ECC.n;
        const u2 = (signature.r * w) % ECC.n;
        
        // Calculate point
        const u1G = this.scalarMultiply(u1, { x: ECC.Gx, y: ECC.Gy });
        const u2Q = this.scalarMultiply(u2, publicKey);
        const point = this.pointAdd(u1G, u2Q);
        
        // Check if point is at infinity
        if (point.x === 0n && point.y === 0n) {
            return false;
        }
        
        // Verify signature
        const v = point.x % ECC.n;
        return v === signature.r;
    }

    // Perform ECDH key exchange
    computeSharedSecret(otherPublicKey) {
        const sharedPoint = this.scalarMultiply(this.privateKey, otherPublicKey);
        // Ensure the point is not at infinity
        if (sharedPoint.x === 0n && sharedPoint.y === 0n) {
            throw new Error('Invalid shared secret: point at infinity');
        }
        return sharedPoint.x;
    }

    // Convert BigInt to hex string
    static bigIntToHex(value) {
        return value.toString(16);
    }

    // Convert hex string to BigInt
    static hexToBigInt(hex) {
        return BigInt('0x' + hex);
    }

    // Convert Uint8Array to hex string
    static bytesToHex(bytes) {
        return Array.from(bytes)
            .map(byte => byte.toString(16).padStart(2, '0'))
            .join('');
    }

    // Convert hex string to Uint8Array
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
}

// Elliptic curve parameters (using secp256k1 - Bitcoin's curve)
ECC.p = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F');
ECC.a = BigInt(0);
ECC.b = BigInt(7);
ECC.Gx = BigInt('0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798');
ECC.Gy = BigInt('0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8');
ECC.n = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

// Example usage
function example() {
    // Generate Alice's ECC key pair
    const alice = new ECC();
    console.log('Alice\'s private key:', ECC.bigIntToHex(alice.getPrivateKey()));
    console.log('Alice\'s public key (x):', ECC.bigIntToHex(alice.getPublicKey().x));
    console.log('Alice\'s public key (y):', ECC.bigIntToHex(alice.getPublicKey().y));
    
    // Generate Bob's ECC key pair
    const bob = new ECC();
    console.log('\nBob\'s private key:', ECC.bigIntToHex(bob.getPrivateKey()));
    console.log('Bob\'s public key (x):', ECC.bigIntToHex(bob.getPublicKey().x));
    console.log('Bob\'s public key (y):', ECC.bigIntToHex(bob.getPublicKey().y));
    
    // Alice signs a message
    const message = 'This is a message to be signed using ECDSA.';
    console.log('\nMessage:', message);
    
    const aliceSignature = alice.sign(message);
    console.log('Alice\'s signature (r):', ECC.bigIntToHex(aliceSignature.r));
    console.log('Alice\'s signature (s):', ECC.bigIntToHex(aliceSignature.s));
    
    // Bob verifies Alice's signature
    const isValid = bob.verify(message, aliceSignature, alice.getPublicKey());
    console.log('Bob verifies Alice\'s signature:', isValid);
    
    // Test with a different message (should fail verification)
    const tamperedMessage = 'This is a tampered message.';
    const isTamperedValid = bob.verify(tamperedMessage, aliceSignature, alice.getPublicKey());
    console.log('Bob verifies tampered message:', isTamperedValid);
    
    // ECDH key exchange
    console.log('\n--- ECDH Key Exchange ---');
    
    // Alice computes shared secret using Bob's public key
    const aliceSharedSecret = alice.computeSharedSecret(bob.getPublicKey());
    console.log('Alice\'s shared secret:', ECC.bigIntToHex(aliceSharedSecret));
    
    // Bob computes shared secret using Alice's public key
    const bobSharedSecret = bob.computeSharedSecret(alice.getPublicKey());
    console.log('Bob\'s shared secret:', ECC.bigIntToHex(bobSharedSecret));
    
    // Verify that both shared secrets are the same
    console.log('Shared secrets match:', aliceSharedSecret === bobSharedSecret);
    
    // Test compressed public key
    console.log('\n--- Compressed Public Key ---');
    const compressedKey = alice.getCompressedPublicKey();
    console.log('Compressed public key:', ECC.bytesToHex(compressedKey));
    
    // Create ECC instance from private key
    const privateKeyHex = ECC.bigIntToHex(alice.getPrivateKey());
    const privateKey = ECC.hexToBigInt(privateKeyHex);
    const aliceFromKey = new ECC(privateKey);
    
    // Verify that public keys match
    const originalPublicKey = alice.getPublicKey();
    const reconstructedPublicKey = aliceFromKey.getPublicKey();
    console.log('Public keys match:', 
        originalPublicKey.x === reconstructedPublicKey.x && 
        originalPublicKey.y === reconstructedPublicKey.y);
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { ECC, example };
} else {
    window.ECC = ECC;
    window.example = example;
}

// Note: To run the example, uncomment the line below or import and call example() from another file
// example();