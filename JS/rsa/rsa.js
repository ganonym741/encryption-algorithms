/**
 * RSA (Rivest-Shamir-Adleman) Implementation
 * This is a simplified educational implementation of RSA
 * Note: For production use, always use well-vetted cryptographic libraries like Node.js's built-in crypto module
 */

class RSA {
    constructor(keySize = 2048) {
        if (keySize < 512) {
            throw new Error('RSA key size must be at least 512 bits for security');
        }
        
        this.generateKeys(keySize);
    }

    // Generate a random prime of approximately bitSize bits
    generatePrime(bitSize) {
        // Miller-Rabin primality test
        const isPrime = (n, k = 5) => {
            if (n <= 1n) return false;
            if (n <= 3n) return true;
            if (n % 2n === 0n) return false;
            
            // Write n-1 as d*2^s
            let d = n - 1n;
            let s = 0n;
            while (d % 2n === 0n) {
                d /= 2n;
                s++;
            }
            
            // Test k times
            for (let i = 0; i < k; i++) {
                const a = this.randomBigInt(2n, n - 2n);
                let x = this.modPow(a, d, n);
                
                if (x === 1n || x === n - 1n) continue;
                
                let continueOuterLoop = false;
                for (let j = 0n; j < s - 1n; j++) {
                    x = this.modPow(x, 2n, n);
                    if (x === n - 1n) {
                        continueOuterLoop = true;
                        break;
                    }
                }
                
                if (continueOuterLoop) continue;
                
                return false;
            }
            
            return true;
        };
        
        // Generate random odd numbers until we find a prime
        let candidate;
        do {
            candidate = this.randomBigInt(
                1n << (BigInt(bitSize) - 1n),
                (1n << BigInt(bitSize)) - 1n
            );
            // Ensure it's odd
            if (candidate % 2n === 0n) candidate += 1n;
        } while (!isPrime(candidate));
        
        return candidate;
    }

    // Generate a random BigInt in the range [min, max]
    randomBigInt(min, max) {
        const range = max - min + 1n;
        const bitsNeeded = range.toString(2).length;
        
        let result = 0n;
        for (let i = 0; i < bitsNeeded; i += 30) {
            // Generate 30 random bits at a time
            const randomValue = Math.floor(Math.random() * (1 << 30));
            result = (result << BigInt(30)) + BigInt(randomValue);
        }
        
        // Ensure result is in the correct range
        result = result % range;
        return result + min;
    }

    // Compute greatest common divisor using Euclidean algorithm
    gcd(a, b) {
        while (b !== 0n) {
            const temp = b;
            b = a % b;
            a = temp;
        }
        return a;
    }

    // Compute modular inverse using extended Euclidean algorithm
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

    // Generate RSA keys
    generateKeys(keySize) {
        // Generate two distinct prime numbers
        const halfKeySize = Math.floor(keySize / 2);
        this.p = this.generatePrime(halfKeySize);
        this.q = this.generatePrime(halfKeySize);
        
        // Ensure p and q are different
        while (this.p === this.q) {
            this.q = this.generatePrime(halfKeySize);
        }
        
        // Compute n = p * q
        this.n = this.p * this.q;
        
        // Compute Euler's totient function: φ(n) = (p-1) * (q-1)
        this.phi = (this.p - 1n) * (this.q - 1n);
        
        // Choose public exponent e
        // Common values are 3, 17, 65537, but we'll use 65537 for security
        this.e = 65537n;
        
        // Ensure e and φ(n) are coprime
        while (this.gcd(this.e, this.phi) !== 1n) {
            this.e += 2n; // Try next odd number
        }
        
        // Compute private exponent d = e^(-1) mod φ(n)
        this.d = this.modInverse(this.e, this.phi);
    }

    // Encrypt a message using public key
    encrypt(message) {
        let data;
        
        if (typeof message === 'string') {
            data = new TextEncoder().encode(message);
        } else {
            data = message;
        }
        
        // RSA can only encrypt data smaller than the modulus
        const maxDataSize = (this.n.toString(2).length / 8) - 11; // PKCS#1 padding
        if (data.length > maxDataSize) {
            throw new Error(`Message too large for RSA. Maximum size: ${maxDataSize} bytes`);
        }
        
        // Convert message directly to BigInt
        let messageBigInt = 0n;
        for (let i = 0; i < data.length; i++) {
            messageBigInt = (messageBigInt << 8n) + BigInt(data[i]);
        }
        
        // Encrypt: c = m^e mod n
        const encryptedBigInt = this.modPow(messageBigInt, this.e, this.n);
        
        // Convert encrypted BigInt to bytes
        const byteLength = Math.ceil(this.n.toString(2).length / 8);
        const encryptedBytes = new Uint8Array(byteLength);
        let temp = encryptedBigInt;
        for (let i = encryptedBytes.length - 1; i >= 0; i--) {
            encryptedBytes[i] = Number(temp % 256n);
            temp /= 256n;
        }
        
        return encryptedBytes;
    }

    // Decrypt a message using private key
    decrypt(ciphertext) {
        // Convert ciphertext to BigInt
        let ciphertextBigInt = 0n;
        for (let i = 0; i < ciphertext.length; i++) {
            ciphertextBigInt = (ciphertextBigInt << 8n) + BigInt(ciphertext[i]);
        }
        
        // Decrypt: m = c^d mod n
        const decryptedBigInt = this.modPow(ciphertextBigInt, this.d, this.n);
        
        // Convert decrypted BigInt to bytes
        const maxBytes = this.n.toString(2).length / 8;
        const decryptedBytes = new Uint8Array(maxBytes);
        let temp = decryptedBigInt;
        for (let i = decryptedBytes.length - 1; i >= 0; i--) {
            decryptedBytes[i] = Number(temp % 256n);
            temp /= 256n;
        }
        
        // Find the start of the actual message (skip leading zeros)
        let messageStart = 0;
        for (let i = 0; i < decryptedBytes.length; i++) {
            if (decryptedBytes[i] !== 0) {
                messageStart = i;
                break;
            }
        }
        
        return decryptedBytes.slice(messageStart);
    }

    // Sign a message using private key
    sign(message) {
        // For simplicity, we'll just encrypt the hash of the message
        // In a real implementation, you would use a proper hash function like SHA-256
        
        let data;
        if (typeof message === 'string') {
            data = new TextEncoder().encode(message);
        } else {
            data = message;
        }
        
        // Simple hash (not cryptographically secure)
        let hash = 0n;
        for (let i = 0; i < data.length; i++) {
            hash = (hash * 31n + BigInt(data[i])) % this.n;
        }
        
        // Sign the hash
        const signature = this.modPow(hash, this.d, this.n);
        
        // Convert signature to bytes
        const signatureBytes = new Uint8Array(this.n.toString(2).length / 8);
        let temp = signature;
        for (let i = signatureBytes.length - 1; i >= 0; i--) {
            signatureBytes[i] = Number(temp % 256n);
            temp /= 256n;
        }
        
        return signatureBytes;
    }

    // Verify a signature using public key
    verify(message, signature) {
        // Compute hash of message
        let data;
        if (typeof message === 'string') {
            data = new TextEncoder().encode(message);
        } else {
            data = message;
        }
        
        // Simple hash (not cryptographically secure)
        let hash = 0n;
        for (let i = 0; i < data.length; i++) {
            hash = (hash * 31n + BigInt(data[i])) % this.n;
        }
        
        // Decrypt signature
        let signatureBigInt = 0n;
        for (let i = 0; i < signature.length; i++) {
            signatureBigInt = (signatureBigInt << 8n) + BigInt(signature[i]);
        }
        
        const decryptedHash = this.modPow(signatureBigInt, this.e, this.n);
        
        // Compare hashes
        return hash === decryptedHash;
    }

    // Get public key as JSON
    getPublicKey() {
        return {
            n: this.n.toString(),
            e: this.e.toString()
        };
    }

    // Get private key as JSON
    getPrivateKey() {
        return {
            n: this.n.toString(),
            e: this.e.toString(),
            d: this.d.toString(),
            p: this.p.toString(),
            q: this.q.toString()
        };
    }

    // Create RSA instance from public key
    static fromPublicKey(publicKey) {
        const rsa = Object.create(RSA.prototype);
        rsa.n = BigInt(publicKey.n);
        rsa.e = BigInt(publicKey.e);
        return rsa;
    }

    // Create RSA instance from private key
    static fromPrivateKey(privateKey) {
        const rsa = Object.create(RSA.prototype);
        rsa.n = BigInt(privateKey.n);
        rsa.e = BigInt(privateKey.e);
        rsa.d = BigInt(privateKey.d);
        rsa.p = BigInt(privateKey.p);
        rsa.q = BigInt(privateKey.q);
        rsa.phi = (rsa.p - 1n) * (rsa.q - 1n);
        return rsa;
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

// Example usage
function example() {
    // Generate RSA keys (512 bits for faster demonstration, use 2048+ for production)
    const rsa = new RSA(512);
    
    // Get public and private keys
    const publicKey = rsa.getPublicKey();
    const privateKey = rsa.getPrivateKey();
    
    console.log('Public Key:', publicKey);
    console.log('Private Key:', privateKey);
    
    // Encrypt and decrypt a message
    const message = 'This is a secret message';
    console.log('Original message:', message);
    
    // Encrypt with public key
    const encrypted = rsa.encrypt(message);
    console.log('Encrypted (hex):', RSA.toHex(encrypted));
    
    // Decrypt with private key
    const decrypted = rsa.decrypt(encrypted);
    const decryptedText = new TextDecoder().decode(decrypted);
    console.log('Decrypted message:', decryptedText);
    
    // Verify encryption/decryption
    console.log('Encryption/Decryption success:', message === decryptedText);
    
    // Sign and verify a message
    const signature = rsa.sign(message);
    console.log('Signature (hex):', RSA.toHex(signature));
    
    const isVerified = rsa.verify(message, signature);
    console.log('Signature verification:', isVerified);
    
    // Test with a different message (should fail verification)
    const tamperedMessage = 'This is a tampered message';
    const isVerifiedTampered = rsa.verify(tamperedMessage, signature);
    console.log('Tampered message verification:', isVerifiedTampered);
    
    // Test creating RSA instance from keys
    console.log('\n--- Testing Key Import/Export ---');
    const rsaFromPublic = RSA.fromPublicKey(publicKey);
    const encryptedWithImportedKey = rsaFromPublic.encrypt(message);
    console.log('Encryption with imported public key successful');
    
    const rsaFromPrivate = RSA.fromPrivateKey(privateKey);
    const decryptedWithImportedKey = new TextDecoder().decode(rsaFromPrivate.decrypt(encryptedWithImportedKey));
    console.log('Decryption with imported private key:', decryptedWithImportedKey);
    console.log('Round-trip with imported keys successful:', message === decryptedWithImportedKey);
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { RSA, example };
} else {
    window.RSA = RSA;
    window.example = example;
}

// Note: To run the example, uncomment the line below or import and call example() from another file
// example();