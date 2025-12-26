# AES (Advanced Encryption Standard)

## Overview

AES (Advanced Encryption Standard) is a symmetric block cipher established by the U.S. National Institute of Standards and Technology (NIST) in 2001. It replaced DES as the standard encryption algorithm for government and commercial use.

## Algorithm Details

### Type

- **Symmetric Block Cipher**
- **Synchronous Operation**

### Key Features

- **Block Size**: 128 bits (16 bytes)
- **Key Sizes**: 128, 192, or 256 bits
- **Rounds**:
  - 10 rounds for 128-bit keys
  - 12 rounds for 192-bit keys
  - 14 rounds for 256-bit keys

### Structure

AES operates on a 4×4 matrix of bytes called the "state". Each round consists of four transformations:

1. **SubBytes**: Non-linear substitution using S-boxes
2. **ShiftRows**: Cyclic shifting of rows
3. **MixColumns**: Linear mixing of columns
4. **AddRoundKey**: XOR with round key

## Implementation Notes

This educational implementation includes:

- Full AES-256 implementation (14 rounds)
- ECB (Electronic Codebook) mode for simplicity
- PKCS#7 padding for block alignment
- Key expansion algorithm

### Security Considerations

⚠️ **This implementation uses ECB mode, which is not secure for most applications.** In production, always use authenticated modes like GCM, CBC with HMAC, or ChaCha20-Poly1305.

## Usage

```javascript
const { AES } = require("./aes.js");

// Create AES instance with 256-bit key (32 bytes)
const key = "my-secret-key-32-bytes-long-123456";
const aes = new AES(key);

// Encrypt data
const plaintext = "This is a secret message";
const encrypted = aes.encrypt(plaintext);

// Decrypt data
const decrypted = aes.decrypt(encrypted);
const decryptedText = new TextDecoder().decode(decrypted);
```

## Pros

1. **Security**: No known practical attacks against AES-256
2. **Performance**: Fast encryption and decryption
3. **Standardization**: Widely adopted and standardized
4. **Hardware Support**: AES-NI instructions in modern CPUs
5. **Flexibility**: Multiple key sizes for different security levels

## Cons

1. **Block Cipher**: Requires padding for messages not matching block size
2. **Key Management**: Same key used for encryption and decryption
3. **Mode Selection**: Requires careful choice of operation mode
4. **Implementation Complexity**: Proper implementation is non-trivial

## Common Use Cases

1. **Data at Rest**: Encrypting files, databases, and storage
2. **Data in Transit**: TLS/SSL for network communications
3. **Disk Encryption**: Full disk encryption systems
4. **VPN**: Secure tunneling protocols
5. **Application Security**: Encrypting sensitive application data

## Security Levels by Key Size

| Key Size | Security Level    | Recommended Use                          |
| -------- | ----------------- | ---------------------------------------- |
| 128 bits | Basic security    | General applications                     |
| 192 bits | Enhanced security | Sensitive data                           |
| 256 bits | Maximum security  | High-value targets, long-term protection |

## Comparison with Other Algorithms

| Algorithm | Block Size | Key Size         | Speed     | Security |
| --------- | ---------- | ---------------- | --------- | -------- |
| AES       | 128 bits   | 128/192/256 bits | Fast      | High     |
| DES       | 64 bits    | 56 bits          | Slow      | Broken   |
| Blowfish  | 64 bits    | 32-448 bits      | Medium    | Medium   |
| ChaCha20  | Stream     | 256 bits         | Very Fast | High     |

## Implementation Files

- [`aes.js`](./aes.js) - Main AES implementation
- [`aes.test.js`](./aes.test.js) - Unit tests
- [`aes.demo.js`](./aes.demo.js) - Educational demonstration
- [`aes.example.js`](./aes.example.js) - Production-ready example

## Testing

Run the AES tests:

```bash
node aes.test.js
```

Or run all tests:

```bash
npm run test:all
```

## Further Reading

1. **NIST FIPS 197**: Official AES specification
2. **"The Design of Rijndael"** by Joan Daemen and Vincent Rijmen
3. **"Cryptography Engineering"** by Ferguson, Schneier, and Kohno

## Security Best Practices

1. **Never use ECB mode** for production applications
2. **Always use authenticated encryption** (AES-GCM)
3. **Generate keys cryptographically** secure random
4. **Implement proper key management** and rotation
5. **Use unique IVs/nonce** for each encryption
6. **Consider side-channel attacks** in implementation

## Performance Notes

- **AES-128**: Fastest, sufficient for most applications
- **AES-192**: Slightly slower, intermediate security
- **AES-256**: Slowest but most secure
- **Hardware Acceleration**: Modern CPUs provide significant speedup

## Real-World Attacks

While AES itself is secure, implementations have been vulnerable to:

- **Timing Attacks**: Side-channel attacks on implementation
- **Padding Oracle**: Attacks on CBC mode implementations
- **Key Recovery**: Attacks on poorly implemented key management

## Migration Path

When moving from this educational implementation to production:

1. Use Node.js built-in `crypto` module
2. Choose appropriate mode (GCM recommended)
3. Implement proper key management
4. Add authentication and integrity checks
5. Consider performance optimizations

## Standards and RFCs

- **FIPS 197**: AES specification
- **NIST SP 800-38A**: Block cipher modes of operation
- **NIST SP 800-38D**: GCM mode specification
- **RFC 3394**: AES key wrapping algorithm
