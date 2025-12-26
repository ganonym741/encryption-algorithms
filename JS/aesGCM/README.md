# AES-GCM (Galois/Counter Mode)

## Overview

AES-GCM (Advanced Encryption Standard - Galois/Counter Mode) is an authenticated encryption algorithm that combines AES counter mode encryption with Galois Message Authentication Code (GMAC). It provides both confidentiality and integrity in a single operation, making it ideal for modern secure communications.

## Algorithm Details

### Type

- **Authenticated Encryption with Associated Data (AEAD)**
- **Symmetric Block Cipher**
- **Synchronous Operation**

### Key Features

- **Block Size**: 128 bits (16 bytes)
- **Key Size**: 128, 192, or 256 bits
- **Nonce Size**: 96 bits (12 bytes recommended)
- **Tag Size**: 128 bits (16 bytes recommended)
- **Associated Data**: Supports additional authenticated data

### Structure

AES-GCM combines two operations:

1. **AES-CTR Encryption**:

   - Counter mode encryption of plaintext
   - Generates ciphertext and keystream
   - Uses incrementing counter for each block

2. **GHASH Authentication**:

   - Galois field multiplication for authentication
   - Processes ciphertext and associated data
   - Generates authentication tag

3. **GCM Construction**:
   - Hash key: EK(0^128) - AES encryption of zero block
   - Counter 0: EK(IV || 0^31 || 1) for tag computation
   - Counter 1+: EK(IV || counter) for encryption

## Implementation Notes

This educational implementation includes:

- Full AES-GCM algorithm with authentication
- Support for associated data (AAD)
- Variable tag sizes (up to 128 bits)
- Counter mode encryption with GMAC authentication

### Security Considerations

⚠️ **This implementation uses Math.random() for nonce generation in examples.** In production, always use cryptographically secure random number generators and never reuse nonces with the same key.

## Usage

```javascript
const { AESGCM } = require("./aesGcm.js");

// Generate 256-bit key and 96-bit nonce
const key = "my-secret-key-32-bytes-long-123456"; // 32 bytes
const nonce = "my-nonce-12b"; // 12 bytes

// Create AES-GCM instance
const aesgcm = new AESGCM(key);

// Encrypt with associated data
const plaintext = "This is a secret message";
const associatedData = "header-info"; // Authenticated but not encrypted
const encrypted = aesgcm.encrypt(plaintext, nonce, associatedData);

// Decrypt and verify
const decrypted = aesgcm.decrypt(
  encrypted.ciphertext,
  nonce,
  encrypted.tag,
  associatedData
);
const decryptedText = new TextDecoder().decode(decrypted);

// Verify authentication
console.log("Authentication successful:", decrypted !== null);

// Extract components
const { ciphertext, tag } = encrypted;
```

## Pros

1. **Authenticated Encryption**: Provides both confidentiality and integrity
2. **High Performance**: Parallelizable encryption and authentication
3. **Widely Adopted**: Standard in TLS 1.3, IPsec, and other protocols
4. **No Padding Required**: Stream-like encryption
5. **Associated Data**: Can authenticate metadata without encryption

## Cons

1. **Nonce Critical**: Reusing nonces completely breaks security
2. **Implementation Complexity**: More complex than basic modes
3. **Limited Data**: Restricts total encrypted data with same key
4. **Tag Size Overhead**: Adds 16 bytes to ciphertext
5. **No Plaintext Authentication**: Associated data must be provided upfront

## Common Use Cases

1. **TLS 1.3**: Default AEAD cipher suite
2. **VPN Communications**: IPsec with AES-GCM
3. **Secure Messaging**: End-to-end encryption with integrity
4. **Database Encryption**: Column-level encryption with integrity
5. **Cloud Storage**: Secure file storage with tamper detection

## Security Levels

| Key Size    | Security Level | Quantum Resistance  | Recommended Use      |
| ----------- | -------------- | ------------------- | -------------------- |
| AES-128-GCM | Strong         | Reduced to 64 bits  | General applications |
| AES-192-GCM | Very Strong    | Reduced to 96 bits  | High-security needs  |
| AES-256-GCM | Maximum        | Reduced to 128 bits | Maximum security     |

## Comparison with Other AEAD Ciphers

| Algorithm         | Key Size         | Tag Size | Speed              | Security Status   |
| ----------------- | ---------------- | -------- | ------------------ | ----------------- |
| AES-GCM           | 128/192/256 bits | 128 bits | Fast (with AES-NI) | Secure            |
| ChaCha20-Poly1305 | 256 bits         | 128 bits | Very Fast          | Secure            |
| AES-CCM           | 128/192/256 bits | 128 bits | Medium             | Secure            |
| AES-OCB           | 128/192/256 bits | 128 bits | Fast               | Patent-encumbered |

## Implementation Files

- [`aesGcm.js`](./aesGcm.js) - Main AES-GCM implementation
- [`aesGcm.test.js`](./aesGcm.test.js) - Unit tests
- [`aesGcm.demo.js`](./aesGcm.demo.js) - Educational demonstration
- [`aesGcm.example.js`](./aesGcm.example.js) - Production-ready example

## Testing

Run the AES-GCM tests:

```bash
node aesGcm.test.js
```

Or run all tests:

```bash
npm run test:all
```

## Further Reading

1. **NIST SP 800-38D**: Recommendation for Block Cipher Modes of Operation
2. **RFC 5116**: An Interface and Algorithms for Authenticated Encryption
3. **"The Galois/Counter Mode of Operation (GCM)"** by McGrew and Viega

## Security Best Practices

1. **Never reuse nonces** with the same key
2. **Use 96-bit nonces** for optimal security
3. **Generate unique nonces** for each encryption
4. **Verify authentication tags** before using plaintext
5. **Limit data volume**: 2^32 blocks per key
6. **Use secure random** number generators for nonces

## Performance Notes

- **Hardware Acceleration**: AES-NI provides significant speedup
- **Parallelization**: Both encryption and authentication parallelizable
- **Memory**: Moderate memory requirements
- **Tag Computation**: Efficient Galois field multiplication
- **Optimization**: Carryless multiplication for GHASH

## Real-World Applications

1. **TLS 1.3**: AES-128-GCM and AES-256-GCM cipher suites
2. **WireGuard**: Modern VPN protocol using ChaCha20-Poly1305 and AES-GCM
3. **SSH**: AES-GCM cipher support
4. **IPsec**: ESP with AES-GCM
5. **WPA3**: Enterprise Wi-Fi security

## GHASH Authentication

GHASH provides authentication using Galois field arithmetic:

1. **Hash Key**: H = EK(0^128)
2. **Block Processing**: Process ciphertext and AAD blocks
3. **Field Multiplication**: Efficient multiplication in GF(2^128)
4. **Tag Generation**: Final XOR with encrypted counter

## Nonce Management

Proper nonce management is critical for security:

1. **Uniqueness**: Never reuse nonce with same key
2. **96-bit Nonces**: Recommended size for efficiency
3. **Counter-based**: Sequential counters for guaranteed uniqueness
4. **Random Nonces**: Cryptographically secure random generation
5. **Key Rotation**: Rotate keys before nonce exhaustion

## Associated Data (AAD)

AAD allows authentication of metadata:

1. **Header Information**: Protocol headers, packet metadata
2. **File Metadata**: Filenames, timestamps, permissions
3. **Network Data**: IP addresses, port numbers
4. **Database Context**: Table names, column information
5. **Application Data**: User IDs, session tokens

## Migration Path

When moving from this educational implementation to production:

1. **Use Node.js crypto**: `crypto.createCipheriv('aes-256-gcm')`
2. **Implement proper nonce management**: Unique per encryption
3. **Add error handling**: Authentication failure detection
4. **Consider performance**: Hardware acceleration where available
5. **Implement key rotation**: Proper key lifecycle management

## Standards and RFCs

- **NIST SP 800-38D**: Recommendation for Block Cipher Modes of Operation
- **RFC 5116**: An Interface and Algorithms for Authenticated Encryption
- **RFC 5288**: AES-GCM Cipher Suites for TLS
- **RFC 8452**: AES-GCM-SIV: Nonce-Misuse-Resistant AEAD

## Quantum Computing Impact

AES-GCM's security is reduced against quantum computers:

- **Grover's Algorithm**: Reduces AES security by half
- **Impact**: AES-256 provides 128-bit quantum security
- **Timeline**: Practical quantum computers may appear in 10-20 years
- **Recommendation**: Use AES-256 for quantum-resistant applications

## Common Pitfalls

1. **Nonce Reuse**: Catastrophic security failure
2. **Ignoring Authentication**: Using ciphertext without tag verification
3. **Wrong Nonce Size**: Using non-standard nonce sizes
4. **Implementation Errors**: Side-channel vulnerabilities
5. **Data Volume Limits**: Exceeding 2^32 blocks per key

## Advanced Topics

1. **AES-GCM-SIV**: Nonce-misuse-resistant variant
2. **AES-GCM with 64-bit Tags**: Reduced overhead for constrained environments
3. **Parallel GHASH**: Hardware-accelerated authentication
4. **Deterministic AEAD**: Same plaintext always produces same ciphertext
5. **Multi-key Security**: Security with related keys

## Test Vectors

Known AES-GCM test vectors for verification:

```
Key: 0000000000000000000000000000000000
IV: 000000000000000000000000000
Plaintext:
AAD:
Ciphertext:
Tag: 58e2fccefa7e3061367f1d57a4e7455a
```

## Comparison with ChaCha20-Poly1305

| Feature    | AES-GCM             | ChaCha20-Poly1305 |
| ---------- | ------------------- | ----------------- |
| Key Size   | 128/192/256 bits    | 256 bits          |
| Nonce Size | 96 bits recommended | 96 bits           |
| Speed      | Fast with AES-NI    | Very Fast         |
| Hardware   | AES-NI support      | Not needed        |
| Security   | Well-studied        | Well-studied      |
| Patent     | Free                | Free              |

## Integration Considerations

When integrating AES-GCM:

1. **Nonce Generation**: Secure and unique per encryption
2. **Tag Storage**: Store tags with ciphertext
3. **Error Handling**: Proper authentication failure handling
4. **Memory Management**: Secure cleanup of sensitive data
5. **Protocol Design**: Include AAD for protocol metadata

## Security Proofs

AES-GCM security is based on:

1. **AES Security**: Underlying block cipher security
2. **Counter Mode Security**: Proven secure if AES is secure
3. **GHASH Security**: Universal hash function properties
4. **Composition Theorem**: Secure composition of encryption and MAC
5. **Reduction**: Security reduces to AES security
