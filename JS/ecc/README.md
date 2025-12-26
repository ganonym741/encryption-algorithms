# ECC (Elliptic Curve Cryptography)

## Overview

Elliptic Curve Cryptography (ECC) is a public-key cryptography approach based on the algebraic structure of elliptic curves over finite fields. ECC offers equivalent security to RSA with smaller key sizes, making it ideal for constrained environments.

## Algorithm Details

### Type

- **Asymmetric Public-Key Cryptography**
- **Synchronous Operation**

### Key Features

- **Key Sizes**: 160-521 bits (commonly 256 bits)
- **Curve Types**: Weierstrass, Montgomery, Edwards curves
- **Operations**: Key generation, encryption, signatures, key exchange
- **Mathematical Basis**: Elliptic Curve Discrete Logarithm Problem (ECDLP)

### Mathematical Foundation

ECC is based on the algebraic structure of elliptic curves:

1. **Elliptic Curve Equation**: y² = x³ + ax + b (mod p)
2. **Point Addition**: Geometric operation on curve points
3. **Scalar Multiplication**: Repeated point addition (kP)
4. **Discrete Logarithm**: Finding k given P and kP is computationally hard

### Elliptic Curve Operations

1. **Point Addition (P + Q)**:

   - Draw line through P and Q
   - Find third intersection with curve
   - Reflect across x-axis

2. **Point Doubling (2P)**:

   - Draw tangent at P
   - Find second intersection with curve
   - Reflect across x-axis

3. **Scalar Multiplication (kP)**:
   - Use double-and-add algorithm
   - Efficient computation of repeated addition

## Implementation Notes

This educational implementation includes:

- secp256k1 curve (Bitcoin's curve)
- ECDSA for digital signatures
- ECDH for key exchange
- Point operations on elliptic curves
- Compressed public key support

### Security Considerations

⚠️ **This implementation uses Math.random() for key generation and simplified hashing for signatures.** In production, always use cryptographically secure random number generators and proper hash functions like SHA-256.

## Usage

```javascript
const { ECC } = require("./ecc.js");

// Generate ECC key pair
const alice = new ECC();
const alicePrivateKey = alice.getPrivateKey();
const alicePublicKey = alice.getPublicKey();

// Sign a message
const message = "This is a message to sign";
const signature = alice.sign(message);

// Verify signature
const isValid = alice.verify(message, signature, alicePublicKey);

// ECDH key exchange
const bob = new ECC();
const aliceSharedSecret = alice.computeSharedSecret(bob.getPublicKey());
const bobSharedSecret = bob.computeSharedSecret(alice.getPublicKey());

// Both shared secrets should be identical
console.log("Shared secrets match:", aliceSharedSecret === bobSharedSecret);

// Get compressed public key
const compressedKey = alice.getCompressedPublicKey();
```

## Pros

1. **Small Key Sizes**: 256-bit ECC ≈ 3072-bit RSA
2. **Fast Performance**: Efficient computations
3. **Low Power Consumption**: Ideal for mobile/IoT devices
4. **Strong Security**: Based on hard mathematical problems
5. **Bandwidth Efficient**: Smaller certificates and signatures

## Cons

1. **Complex Mathematics**: More complex than RSA
2. **Implementation Challenges**: Side-channel attack risks
3. **Patent Issues**: Some curves had patent restrictions
4. **Quantum Vulnerability**: Vulnerable to quantum computers
5. **Standardization**: Multiple curve standards exist

## Common Use Cases

1. **Bitcoin/Ethereum**: Digital signatures for transactions
2. **TLS/SSL**: ECDHE key exchange in HTTPS
3. **Mobile Security**: Device authentication and key exchange
4. **IoT Devices**: Constrained environment cryptography
5. **Secure Messaging**: End-to-end encryption protocols

## Security Levels by Key Size

| Key Size | RSA Equivalent | Security Level | Quantum Resistance | Recommended Use  |
| -------- | -------------- | -------------- | ------------------ | ---------------- |
| 160 bits | 1024 bits      | Basic          | Broken             | Legacy systems   |
| 224 bits | 2048 bits      | Good           | Broken             | General use      |
| 256 bits | 3072 bits      | Strong         | Broken             | Current standard |
| 384 bits | 7680 bits      | Very Strong    | Broken             | High security    |
| 521 bits | 15360 bits     | Maximum        | Broken             | Maximum security |

## Standard Curves

| Curve Name | Key Size | Type       | Use Case          |
| ---------- | -------- | ---------- | ----------------- |
| secp256k1  | 256 bits | Koblitz    | Bitcoin, Ethereum |
| secp256r1  | 256 bits | Random     | TLS, Apple        |
| secp384r1  | 384 bits | Random     | High security     |
| Curve25519 | 256 bits | Montgomery | Modern protocols  |
| Ed25519    | 256 bits | Edwards    | Fast signatures   |

## Comparison with Other Algorithms

| Algorithm    | Key Size  | Speed     | Security | Quantum Resistance |
| ------------ | --------- | --------- | -------- | ------------------ |
| ECC          | 256 bits  | Fast      | Strong   | No                 |
| RSA          | 3072 bits | Slow      | Strong   | No                 |
| Ed25519      | 256 bits  | Very Fast | Strong   | No                 |
| Post-Quantum | Varies    | Varies    | Strong   | Yes                |

## Implementation Files

- [`ecc.js`](./ecc.js) - Main ECC implementation
- [`ecc.test.js`](./ecc.test.js) - Unit tests
- [`ecc.demo.js`](./ecc.demo.js) - Educational demonstration
- [`ecc.example.js`](./ecc.example.js) - Production-ready example

## Testing

Run the ECC tests:

```bash
node ecc.test.js
```

Or run all tests:

```bash
npm run test:all
```

## Further Reading

1. **"Guide to Elliptic Curve Cryptography"** by Hankerson, Menezes, and Vanstone
2. **"Mastering Bitcoin"** by Andreas Antonopoulos
3. **SEC 1**: Elliptic Curve Cryptography Standards

## Security Best Practices

1. **Use standardized curves** (NIST, Brainpool, Curve25519)
2. **Validate public keys** (check if on curve)
3. **Use constant-time operations** for sensitive calculations
4. **Generate private keys with secure random** number generators
5. **Implement proper domain parameters** validation
6. **Consider side-channel attacks** in implementation

## Performance Notes

- **Scalar Multiplication**: Most expensive operation
- **Point Addition**: Faster than multiplication
- **Key Generation**: Fast compared to RSA
- **Signature Verification**: Faster than RSA
- **Memory Usage**: Minimal memory requirements

## Real-World Attacks

1. **Invalid Curve Attacks**: Using malicious curve parameters
2. **Small Subgroup Attacks**: Exploiting curve properties
3. **Twist Security**: Attacks on curve twists
4. **Side-Channel Attacks**: Timing, power analysis
5. **Fault Attacks**: Inducing computation errors

## ECDSA (Elliptic Curve Digital Signature Algorithm)

ECDSA is the most common ECC signature scheme:

1. **Key Generation**:

   - Private key: random integer d
   - Public key: point Q = dG

2. **Signing**:

   - Generate random nonce k
   - Compute point (x1, y1) = kG
   - Calculate r = x1 mod n
   - Calculate s = k^(-1)(hash + rd) mod n

3. **Verification**:
   - Compute w = s^(-1) mod n
   - Compute u1 = hash × w mod n
   - Compute u2 = r × w mod n
   - Compute point (x, y) = u1G + u2Q
   - Verify r = x mod n

## ECDH (Elliptic Curve Diffie-Hellman)

ECDH enables secure key exchange:

1. **Setup**:

   - Both parties agree on curve parameters
   - Base point G is public

2. **Exchange**:

   - Alice generates private key a, computes A = aG
   - Bob generates private key b, computes B = bG
   - Exchange public keys A and B

3. **Shared Secret**:
   - Alice computes S = bA = baG
   - Bob computes S = aB = abG
   - Both parties now share point S

## Migration Path

When moving from this educational implementation to production:

1. Use Node.js built-in `crypto` module with ECDH
2. Use standardized curves (Curve25519 recommended)
3. Implement proper key validation
4. Add side-channel protections
5. Consider post-quantum alternatives for long-term security

## Standards and RFCs

- **SEC 1**: Elliptic Curve Cryptography
- **RFC 6090**: Fundamental Elliptic Curve Cryptography Algorithms
- **RFC 7748**: Elliptic Curves for Security (Curve25519, Curve448)
- **FIPS 186-4**: Digital Signature Standard (ECDSA)

## Quantum Computing Impact

ECC is vulnerable to quantum computers:

- **Shor's Algorithm**: Can solve elliptic curve discrete logarithm
- **Timeline**: Practical quantum computers may appear in 10-20 years
- **Impact**: All ECC variants will be broken
- **Migration**: Plan transition to post-quantum cryptography

## Curve Selection Guidelines

When choosing an elliptic curve:

1. **Security Level**: Choose based on required security
2. **Performance**: Consider computational efficiency
3. **Standardization**: Use widely accepted standards
4. **Implementation**: Consider available library support
5. **Future-Proofing**: Consider quantum resistance

## Common Pitfalls

1. **Weak Random Numbers**: Using predictable nonce k in signatures
2. **Improper Validation**: Not validating received public keys
3. **Side-Channel Leaks**: Timing variations in operations
4. **Reuse of Nonces**: Reusing k in ECDSA compromises private key
5. **Wrong Curve Operations**: Mixing points from different curves

## Advanced Topics

1. **Pairing-Based Cryptography**: Bilinear maps on curves
2. **Zero-Knowledge Proofs**: Privacy-preserving protocols
3. **Threshold Cryptography**: Distributed key generation
4. **Homomorphic Encryption**: Computation on encrypted data
5. **Post-Quantum ECC**: Quantum-resistant variants
