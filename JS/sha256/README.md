# SHA-256 (Secure Hash Algorithm 256-bit)

## Overview

SHA-256 is a cryptographic hash function that belongs to the SHA-2 family, designed by the U.S. National Security Agency (NSA) and published by the National Institute of Standards and Technology (NIST) in 2001. It produces a fixed 256-bit (32-byte) hash value from an input message of any length.

## Algorithm Details

### Type
- **Cryptographic Hash Function**
- **One-Way Function**
- **Synchronous Operation**

### Key Features
- **Output Size**: 256 bits (32 bytes)
- **Input Size**: Unlimited (practically)
- **Block Size**: 512 bits (64 bytes)
- **Rounds**: 64 compression rounds

### Structure

SHA-256 processes data in 512-bit blocks through the following steps:

1. **Message Padding**:
   - Append a single '1' bit
   - Append '0' bits until length ≡ 448 mod 512
   - Append 64-bit original message length

2. **Message Schedule**:
   - Divide padded message into 512-bit blocks
   - Expand each block into 64 32-bit words

3. **Compression**:
   - Initialize hash values with constants
   - Process each block through 64 rounds
   - Update hash values after each block

4. **Output**: Final 256-bit hash value

## Implementation Notes

This educational implementation includes:
- Full SHA-256 algorithm with 64 rounds
- HMAC-SHA256 support for message authentication
- File hashing capability
- Hex and binary conversion utilities

### Security Considerations
⚠️ **This implementation is for educational purposes only.** In production, always use well-vetted cryptographic libraries like Node.js's built-in `crypto` module.

## Usage

```javascript
const { SHA256 } = require('./sha256.js');

// Hash a string
const message = 'This is a message to hash';
const hash = SHA256.hash(message);
console.log('SHA-256 Hash:', hash);

// Hash binary data
const data = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]); // "Hello"
const dataHash = SHA256.hash(data);

// HMAC for message authentication
const key = 'secret-key';
const hmac = SHA256.hmac(key, message);

// Hash a file (in browser environment)
const fileInput = document.getElementById('file-input');
const file = fileInput.files[0];
const fileHash = await SHA256.hashFile(file);
```

## Pros

1. **Security**: No known practical collisions or preimage attacks
2. **Standardization**: Widely adopted and standardized
3. **Performance**: Fast computation on modern hardware
4. **Deterministic**: Same input always produces same output
5. **Fixed Output**: Consistent 256-bit output regardless of input size

## Cons

1. **One-Way**: Cannot reverse hash to original input
2. **Collision Possibility**: Theoretically possible (2^128 operations)
3. **Quantum Vulnerability**: Grover's algorithm reduces security to 128 bits
4. **Memory Usage**: Requires storing entire message for processing
5. **Not Encryption**: Cannot be used to encrypt data (only verify integrity)

## Common Use Cases

1. **Password Storage**: Hashing passwords with salt
2. **Data Integrity**: Verifying file/data integrity
3. **Digital Signatures**: Hashing messages before signing
4. **Blockchain**: Block hashing in cryptocurrencies
5. **Authentication**: HMAC for API authentication
6. **Version Control**: Git commit hashes
7. **Software Distribution**: Verifying download integrity

## Security Properties

| Property | Description | SHA-256 Status |
|----------|-------------|-----------------|
| Preimage Resistance | Infeasible to find input for given hash | ✅ Strong |
| Second Preimage Resistance | Infeasible to find second input for same hash | ✅ Strong |
| Collision Resistance | Infeasible to find two inputs with same hash | ✅ Strong |
| Avalanche Effect | Small input change → completely different hash | ✅ Strong |

## Comparison with Other Hash Functions

| Algorithm | Output Size | Security Status | Speed |
|-----------|-------------|-----------------|-------|
| SHA-256 | 256 bits | Secure | Fast |
| SHA-1 | 160 bits | Broken (collisions found) | Fast |
| SHA-3 | 256 bits | Secure | Medium |
| MD5 | 128 bits | Broken (collisions trivial) | Very Fast |
| BLAKE2 | 256 bits | Secure | Very Fast |

## Implementation Files

- [`sha256.js`](./sha256.js) - Main SHA-256 implementation
- [`sha256.test.js`](./sha256.test.js) - Unit tests
- [`sha256.demo.js`](./sha256.demo.js) - Educational demonstration
- [`sha256.example.js`](./sha256.example.js) - Production-ready example

## Testing

Run the SHA-256 tests:
```bash
node sha256.test.js
```

Or run all tests:
```bash
npm run test:all
```

## Further Reading

1. **FIPS 180-4**: Secure Hash Standard
2. **"Handbook of Applied Cryptography"** by Menezes, van Oorschot, and Vanstone
3. **"Cryptography Engineering"** by Ferguson, Schneier, and Kohno

## Security Best Practices

1. **Always use salt** for password hashing (bcrypt, scrypt, Argon2 preferred)
2. **Use HMAC** for message authentication
3. **Never use raw hash** for password storage
4. **Consider SHA-3** for new designs (quantum-resistant)
5. **Implement constant-time comparison** for hash verification
6. **Use pepper** for additional password security

## Performance Notes

- **Hardware Acceleration**: Some CPUs support SHA instructions
- **Memory Usage**: Requires storing entire message
- **Streaming**: Can be implemented for large files
- **Parallel Processing**: Limited parallelization opportunities

## Real-World Applications

1. **Bitcoin**: Mining and block verification
2. **TLS/SSL**: Certificate fingerprinting
3. **Git**: Commit and object identification
4. **Package Managers**: Package integrity verification
5. **Password Systems**: As component of PBKDF2, bcrypt

## Test Vectors

Known SHA-256 test vectors for verification:

```
SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
SHA-256("The quick brown fox jumps over the lazy dog") = d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb7620f65c7b6f1b76b1
```

## HMAC-SHA256

HMAC (Hash-based Message Authentication Code) combines SHA-256 with a secret key:

```
HMAC(key, message) = H((K ⊕ opad) || H((K ⊕ ipad) || message))
```

Where:
- H = SHA-256
- K = Secret key (padded or truncated to 64 bytes)
- ⊕ = XOR
- opad = 0x5c5c...5c (64 bytes)
- ipad = 0x3636...36 (64 bytes)
- || = Concatenation

## Migration Path

When moving from this educational implementation to production:
1. Use Node.js built-in `crypto.createHash('sha256')`
2. For passwords, use bcrypt, scrypt, or Argon2
3. For authentication, use HMAC with proper key management
4. Consider hardware acceleration for performance-critical applications

## Standards and RFCs

- **FIPS 180-4**: Secure Hash Standard
- **RFC 6234**: US Secure Hash Algorithms
- **RFC 2104**: HMAC: Keyed-Hashing for Message Authentication

## Quantum Computing Impact

SHA-256's security is reduced against quantum attacks:
- **Grover's Algorithm**: Reduces security from 256 to 128 bits
- **Timeline**: Practical quantum computers may appear in 10-20 years
- **Recommendation**: SHA-256 still provides 128-bit security against quantum attacks
- **Alternatives**: SHA-3 or SHA-512 for higher quantum resistance

## Hash Length Extension Attack

SHA-256 is vulnerable to length extension attacks:
- **Vulnerability**: Can extend hash without knowing original message
- **Mitigation**: Use HMAC instead of raw hash for authentication
- **Impact**: Affects protocols using raw hash for message authentication
- **Solution**: Always use HMAC for authentication purposes
