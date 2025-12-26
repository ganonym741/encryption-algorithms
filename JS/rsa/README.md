# RSA (Rivest-Shamir-Adleman)

## Overview

RSA is one of the first public-key cryptosystems and is widely used for secure data transmission. It was developed in 1977 by Ron Rivest, Adi Shamir, and Leonard Adleman, whose initials form the name RSA.

## Algorithm Details

### Type

- **Asymmetric Public-Key Cryptosystem**
- **Synchronous Operation**

### Key Features

- **Key Sizes**: Typically 1024, 2048, or 4096 bits
- **Operations**: Encryption, Decryption, Digital Signatures, Key Exchange
- **Mathematical Basis**: Integer factorization problem

### Mathematical Foundation

RSA relies on the practical difficulty of factoring the product of two large prime numbers:

1. **Key Generation**:

   - Generate two large prime numbers p and q
   - Compute n = p × q (modulus)
   - Compute φ(n) = (p-1) × (q-1) (Euler's totient)
   - Choose public exponent e (typically 65537)
   - Compute private exponent d = e^(-1) mod φ(n)

2. **Encryption**: c = m^e mod n
3. **Decryption**: m = c^d mod n

## Implementation Notes

This educational implementation includes:

- Variable key size support (512-4096+ bits)
- Miller-Rabin primality testing
- Modular exponentiation
- Digital signature functionality
- Key import/export capabilities

### Security Considerations

⚠️ **This implementation uses simplified hashing for signatures and Math.random() for key generation.** In production, always use cryptographically secure random number generators and proper hash functions like SHA-256.

## Usage

```javascript
const { RSA } = require("./rsa.js");

// Generate RSA key pair (2048 bits recommended for production)
const rsa = new RSA(2048);

// Get public and private keys
const publicKey = rsa.getPublicKey();
const privateKey = rsa.getPrivateKey();

// Encrypt with public key
const plaintext = "This is a secret message";
const encrypted = rsa.encrypt(plaintext);

// Decrypt with private key
const decrypted = rsa.decrypt(encrypted);
const decryptedText = new TextDecoder().decode(decrypted);

// Sign a message
const signature = rsa.sign(plaintext);

// Verify signature
const isValid = rsa.verify(plaintext, signature);
```

## Pros

1. **Security**: Based on well-studied mathematical problems
2. **Standardization**: Widely adopted and standardized
3. **Versatility**: Supports encryption, signatures, and key exchange
4. **Key Distribution**: Public key can be freely shared
5. **Digital Signatures**: Provides non-repudiation

## Cons

1. **Performance**: Slower than symmetric algorithms
2. **Key Size**: Requires large keys for security
3. **Quantum Vulnerability**: Vulnerable to quantum computers
4. **Implementation Complexity**: Requires careful implementation
5. **Padding Attacks**: Vulnerable if padding is not properly implemented

## Common Use Cases

1. **Digital Signatures**: Code signing, document authentication
2. **Key Exchange**: Establishing symmetric keys for secure communication
3. **Secure Email**: PGP, S/MIME email encryption
4. **SSL/TLS**: Web security certificates
5. **Authentication**: SSH, VPN connections

## Security Levels by Key Size

| Key Size  | Security Level     | Quantum Resistance | Recommended Use     |
| --------- | ------------------ | ------------------ | ------------------- |
| 1024 bits | Basic (deprecated) | Broken             | Legacy systems only |
| 2048 bits | Good until ~2030   | Broken             | Current standard    |
| 3072 bits | Better until ~2040 | Broken             | High-security needs |
| 4096 bits | Best until ~2050   | Broken             | Maximum security    |

## Comparison with Other Algorithms

| Algorithm | Key Size     | Speed     | Quantum Resistance | Use Case                 |
| --------- | ------------ | --------- | ------------------ | ------------------------ |
| RSA       | 2048+ bits   | Slow      | No                 | Signatures, Key Exchange |
| ECC       | 256+ bits    | Medium    | No                 | Mobile, IoT              |
| Ed25519   | 256 bits     | Fast      | No                 | Modern signatures        |
| AES       | 128/256 bits | Very Fast | No                 | Bulk encryption          |

## Implementation Files

- [`rsa.js`](./rsa.js) - Main RSA implementation
- [`rsa.test.js`](./rsa.test.js) - Unit tests
- [`rsa.demo.js`](./rsa.demo.js) - Educational demonstration
- [`rsa.example.js`](./rsa.example.js) - Production-ready example

## Testing

Run the RSA tests:

```bash
node rsa.test.js
```

Or run all tests:

```bash
npm run test:all
```

## Further Reading

1. **PKCS #1**: RSA Cryptography Standard
2. **"Handbook of Applied Cryptography"** by Menezes, van Oorschot, and Vanstone
3. **"Applied Cryptography"** by Bruce Schneier

## Security Best Practices

1. **Minimum 2048-bit keys** for new implementations
2. **Use proper padding** (OAEP for encryption, PSS for signatures)
3. **Generate keys with secure random** number generators
4. **Implement side-channel protection** against timing attacks
5. **Use constant-time operations** for sensitive operations
6. **Regularly rotate keys** and use proper key management

## Performance Notes

- **Key Generation**: Most expensive operation
- **Encryption**: Faster with smaller public exponent (65537)
- **Decryption**: Slower than encryption
- **Verification**: Faster than signing
- **Hardware Acceleration**: Some CPUs support RSA operations

## Real-World Attacks

1. **Timing Attacks**: Kocher's attack on implementation timing
2. **Bleichenbacher's Attack**: Padding oracle attack
3. **Factoring Advances**: Improved factoring algorithms
4. **Side-Channel Attacks**: Power analysis, electromagnetic attacks
5. **Mathematical Advances**: Continued research in factoring

## Migration Path

When moving from this educational implementation to production:

1. Use Node.js built-in `crypto` module
2. Implement OAEP padding for encryption
3. Use PSS padding for signatures
4. Add proper random number generation
5. Implement side-channel protections

## Standards and RFCs

- **RFC 8017**: PKCS #1: RSA Cryptography Standard
- **RFC 3447**: Previous PKCS #1 standard
- **FIPS 186-4**: Digital Signature Standard
- **NIST SP 800-57**: Key Management Guidelines

## Quantum Computing Impact

RSA is vulnerable to quantum computers due to Shor's algorithm:

- **Quantum Threat**: Can factor large numbers efficiently
- **Timeline**: Practical quantum computers may appear in 10-20 years
- **Migration**: Plan transition to post-quantum cryptography
- **Alternatives**: Lattice-based, hash-based, or code-based cryptography

## Key Management Best Practices

1. **Generate keys in secure environments**
2. **Store private keys with strong encryption**
3. **Use hardware security modules (HSMs) for high-value keys**
4. **Implement key rotation policies**
5. **Securely destroy old keys when no longer needed**
6. **Use key escrow for business continuity**
