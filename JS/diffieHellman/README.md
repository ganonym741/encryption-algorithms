# Diffie-Hellman Key Exchange

## Overview

Diffie-Hellman (DH) is a cryptographic protocol that allows two parties to establish a shared secret over an insecure communication channel. It was one of the first public-key protocols and enables secure key exchange without prior shared secrets.

## Algorithm Details

### Type

- **Key Exchange Protocol**
- **Asymmetric Cryptography**
- **Synchronous Operation**

### Key Features

- **Purpose**: Establish shared secret without prior communication
- **Security Basis**: Discrete logarithm problem
- **Key Sizes**: Typically 1024-4096 bits
- **Perfect Forward Secrecy**: Each session uses unique keys

### Mathematical Foundation

The protocol relies on the difficulty of solving the discrete logarithm problem:

1. **Setup**:

   - Choose a large prime p
   - Choose a generator g (primitive root modulo p)
   - These parameters can be public and shared

2. **Key Exchange**:

   - Alice generates private key a (1 < a < p-1)
   - Alice computes public key A = g^a mod p
   - Bob generates private key b (1 < b < p-1)
   - Bob computes public key B = g^b mod p
   - Alice and Bob exchange public keys A and B

3. **Shared Secret**:
   - Alice computes S = B^a mod p = (g^b)^a mod p = g^(ba) mod p
   - Bob computes S = A^b mod p = (g^a)^b mod p = g^(ab) mod p
   - Both parties now share the same secret S

## Implementation Notes

This educational implementation includes:

- Support for predefined groups (1024-bit, 2048-bit MODP groups)
- Miller-Rabin primality testing for custom groups
- Man-in-the-middle attack demonstration
- BigInt-based modular arithmetic
- Key generation and exchange utilities

### Security Considerations

⚠️ **This implementation uses Math.random() for key generation and is vulnerable to timing attacks.** In production, always use cryptographically secure random number generators and constant-time operations.

## Usage

```javascript
const { DiffieHellman } = require("./diffieHellman.js");

// Create Alice's Diffie-Hellman instance
const alice = new DiffieHellman("MODP_2048"); // Use 2048-bit group

// Create Bob's Diffie-Hellman instance with same parameters
const bobParams = alice.getParameters();
const bob = new DiffieHellman(bobParams.p, bobParams.g);

// Exchange public keys
const alicePublicKey = alice.getPublicKey();
const bobPublicKey = bob.getPublicKey();

// Compute shared secrets
const aliceSecret = alice.computeSharedSecret(bobPublicKey);
const bobSecret = bob.computeSharedSecret(alicePublicKey);

// Both secrets should be identical
console.log("Shared secrets match:", aliceSecret === bobSecret);

// Use shared secret as encryption key
const secretBytes = DiffieHellman.bigIntToBytes(aliceSecret);
```

## Pros

1. **Perfect Forward Secrecy**: Each session uses unique keys
2. **No Prior Secrets**: Establishes secure channel without prior communication
3. **Standardization**: Widely adopted and standardized
4. **Flexibility**: Works with various group parameters
5. **Foundation**: Basis for many modern protocols

## Cons

1. **Man-in-the-Middle Vulnerability**: Requires authentication
2. **Performance**: Slower than symmetric key operations
3. **Key Size**: Requires large parameters for security
4. **No Authentication**: Must be combined with authentication mechanisms
5. **Quantum Vulnerability**: Vulnerable to quantum computers

## Common Use Cases

1. **TLS/SSL**: Establishing secure connections
2. **SSH**: Secure shell connections
3. **VPN**: Virtual private network key exchange
4. **Messaging**: End-to-end encryption protocols
5. **IPsec**: Internet Protocol Security

## Security Levels by Group Size

| Group Size | Security Level     | Quantum Resistance | Recommended Use     |
| ---------- | ------------------ | ------------------ | ------------------- |
| 1024 bits  | Basic (deprecated) | Broken             | Legacy systems only |
| 2048 bits  | Good until ~2030   | Broken             | Current minimum     |
| 3072 bits  | Better until ~2040 | Broken             | High-security needs |
| 4096 bits  | Best until ~2050   | Broken             | Maximum security    |

## Comparison with Other Key Exchange Protocols

| Protocol         | Key Size   | Speed  | Quantum Resistance | Authentication |
| ---------------- | ---------- | ------ | ------------------ | -------------- |
| Diffie-Hellman   | 2048+ bits | Slow   | No                 | Required       |
| ECDH             | 256+ bits  | Medium | No                 | Required       |
| RSA Key Exchange | 2048+ bits | Slow   | No                 | Built-in       |
| Post-Quantum KEM | Varies     | Varies | Yes                | Varies         |

## Implementation Files

- [`diffieHellman.js`](./diffieHellman.js) - Main Diffie-Hellman implementation
- [`diffieHellman.test.js`](./diffieHellman.test.js) - Unit tests
- [`diffieHellman.demo.js`](./diffieHellman.demo.js) - Educational demonstration
- [`diffieHellman.example.js`](./diffieHellman.example.js) - Production-ready example

## Testing

Run the Diffie-Hellman tests:

```bash
node diffieHellman.test.js
```

Or run all tests:

```bash
npm run test:all
```

## Further Reading

1. **RFC 3526**: More Modular Exponential (MODP) Diffie-Hellman groups
2. **"Handbook of Applied Cryptography"** by Menezes, van Oorschot, and Vanstone
3. **"Cryptography Engineering"** by Ferguson, Schneier, and Kohno

## Security Best Practices

1. **Use standardized groups** (RFC 3526 MODP groups)
2. **Minimum 2048-bit parameters** for new implementations
3. **Always authenticate** the exchange (digital signatures, certificates)
4. **Use constant-time operations** for sensitive calculations
5. **Generate private keys with secure random** number generators
6. **Implement proper validation** of received parameters

## Performance Notes

- **Exponentiation**: Most expensive operation
- **Key Generation**: Computationally intensive
- **Public Key Operations**: Faster than private key operations
- **Memory Usage**: Minimal memory requirements
- **Parallel Processing**: Limited opportunities for parallelization

## Real-World Attacks

1. **Man-in-the-Middle**: Active attacker intercepts and modifies communications
2. **Logjam Attack**: Exploits export-grade 512-bit DH parameters
3. **Small Subgroup Attacks**: Malicious parameters in small subgroups
4. **Timing Attacks**: Side-channel attacks on implementation
5. **Invalid Curve Attacks**: For elliptic curve variants

## Variants and Extensions

1. **Elliptic Curve Diffie-Hellman (ECDH)**:

   - Smaller keys for equivalent security
   - Better performance
   - Same security assumptions on elliptic curves

2. **Authenticated Diffie-Hellman**:

   - Combines DH with digital signatures
   - Prevents man-in-the-middle attacks
   - Used in TLS, SSH

3. **Group Key Exchange**:
   - Extends to multiple participants
   - Used in group messaging protocols

## Migration Path

When moving from this educational implementation to production:

1. Use Node.js built-in `crypto.diffieHellman`
2. Use standardized parameters (RFC 3526)
3. Implement proper authentication
4. Add validation of received parameters
5. Consider ECDH for better performance

## Standards and RFCs

- **RFC 2631**: Diffie-Hellman Key Agreement Method
- **RFC 3526**: More Modular Exponential (MODP) Diffie-Hellman groups
- **RFC 5114**: Additional Diffie-Hellman Groups
- **NIST SP 800-56A**: Recommendation for Pair-Wise Key Establishment

## Quantum Computing Impact

Diffie-Hellman is vulnerable to quantum computers:

- **Shor's Algorithm**: Can solve discrete logarithm efficiently
- **Timeline**: Practical quantum computers may appear in 10-20 years
- **Impact**: All DH variants (including ECDH) will be broken
- **Migration**: Plan transition to post-quantum key exchange

## Perfect Forward Secrecy

Diffie-Hellman provides Perfect Forward Secrecy (PFS):

- **Definition**: Compromise of long-term keys doesn't compromise past sessions
- **Benefit**: Enhanced security for communications
- **Implementation**: Use ephemeral keys for each session
- **Protocols**: TLS 1.3 requires PFS ciphersuites

## Integration with Authentication

Diffie-Hellman must be combined with authentication:

1. **Digital Signatures**: Sign the DH parameters
2. **Certificates**: Verify identity through PKI
3. **Pre-Shared Keys**: Authenticate with existing secrets
4. **Public Key Infrastructure**: Establish trust relationships

## Common Pitfalls

1. **Using Small Parameters**: 1024-bit or smaller groups are insecure
2. **Missing Authentication**: Vulnerable to man-in-the-middle attacks
3. **Static Keys**: Reusing keys reduces forward secrecy
4. **Improper Validation**: Not validating received parameters
5. **Weak Random Numbers**: Using predictable random generators
