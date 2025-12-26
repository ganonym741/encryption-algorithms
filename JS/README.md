# Encryption Algorithms Implementation

This directory contains educational implementations of various encryption algorithms, hash functions, and cryptographic protocols. These implementations are designed for learning purposes and should not be used in production environments.

## 🚨 Security Notice

**These implementations are for educational purposes only.** For production use, always use well-vetted cryptographic libraries like Node.js's built-in `crypto` module or established libraries such as `crypto-js`, `node-forge`, or `libsodium`.

## Algorithms Overview

### Symmetric Encryption Algorithms

| Algorithm               | Type                     | Key Size         | Block Size | Mode              | Synchronous |
| ----------------------- | ------------------------ | ---------------- | ---------- | ----------------- | ----------- |
| [AES](./aes/)           | Block Cipher             | 128/192/256 bits | 128 bits   | ECB (educational) | ✅          |
| [DES](./des/)           | Block Cipher             | 56 bits          | 64 bits    | ECB (educational) | ✅          |
| [Blowfish](./blowfish/) | Block Cipher             | 32-448 bits      | 64 bits    | ECB (educational) | ✅          |
| [ChaCha20](./chacha20/) | Stream Cipher            | 256 bits         | N/A        | Stream            | ✅          |
| [AES-GCM](./aesGCM/)    | Authenticated Encryption | 128/192/256 bits | 128 bits   | GCM               | ✅          |

### Asymmetric Encryption Algorithms

| Algorithm     | Type       | Key Size       | Purpose                         | Synchronous |
| ------------- | ---------- | -------------- | ------------------------------- | ----------- |
| [RSA](./rsa/) | Public Key | 512-4096+ bits | Encryption/Signing              | ✅          |
| [ECC](./ecc/) | Public Key | 256-521 bits   | Encryption/Signing/Key Exchange | ✅          |

### Hash Functions

| Algorithm            | Output Size | Purpose             | Synchronous |
| -------------------- | ----------- | ------------------- | ----------- |
| [SHA-256](./sha256/) | 256 bits    | Data Integrity/HMAC | ✅          |

### Key Exchange Protocols

| Algorithm                          | Type         | Key Size        | Purpose             | Synchronous |
| ---------------------------------- | ------------ | --------------- | ------------------- | ----------- |
| [Diffie-Hellman](./diffieHellman/) | Key Exchange | 1024-2048+ bits | Secure Key Exchange | ✅          |

## Project Structure

```
JS/
├── README.md                 # This file
├── package.json              # Project configuration
├── testUtils.js              # Testing utilities
├── testRunner.html           # Browser-based test runner
├── runAllTests.js            # Node.js test runner
├── all.algo.js               # Run all algorithm examples
├── all.example.js            # Run all production-ready examples
├── aes/                      # AES implementation
├── des/                      # DES implementation
├── blowfish/                 # Blowfish implementation
├── chacha20/                 # ChaCha20 implementation
├── aesGCM/                   # AES-GCM implementation
├── rsa/                      # RSA implementation
├── ecc/                      # ECC implementation
├── sha256/                   # SHA-256 implementation
└── diffieHellman/            # Diffie-Hellman implementation
```

## Usage

### Running All Algorithms

```bash
# Run all basic algorithm examples
npm run algo:all

# Run all production-ready examples
npm run example:all

# Run all tests
npm run test:all
```

### Individual Algorithm Usage

Each algorithm can be used independently:

```javascript
// Example with AES
const { AES } = require("./aes/aes.js");
const aes = new AES("63f4945d921d599f27ae4fdf5bada3f1");
const encrypted = aes.encrypt("Hello, World!");
const decrypted = aes.decrypt(encrypted);
```

### Testing

#### Browser Testing

Open `testRunner.html` in a web browser to run tests with a graphical interface.

#### Node.js Testing

```bash
node runAllTests.js
```

## Algorithm Characteristics

### Symmetric vs Asymmetric

- **Symmetric Algorithms** (AES, DES, Blowfish, ChaCha20, AES-GCM):

  - Use the same key for encryption and decryption
  - Generally faster than asymmetric algorithms
  - Suitable for encrypting large amounts of data
  - Key distribution is a challenge

- **Asymmetric Algorithms** (RSA, ECC):
  - Use different keys for encryption and decryption
  - Solve key distribution problems
  - Slower than symmetric algorithms
  - Often used for key exchange and digital signatures

### Block vs Stream Ciphers

- **Block Ciphers** (AES, DES, Blowfish):

  - Encrypt data in fixed-size blocks
  - Require padding for incomplete blocks
  - Can operate in various modes (ECB, CBC, GCM, etc.)

- **Stream Ciphers** (ChaCha20):
  - Encrypt data one bit or byte at a time
  - Don't require padding
  - Often faster for streaming data

### Hash Functions

- **SHA-256**:
  - One-way function (cannot be reversed)
  - Fixed output size regardless of input size
  - Used for data integrity and password storage
  - Small input changes produce completely different outputs

## Security Considerations

### Implementation Limitations

1. **Random Number Generation**: Uses `Math.random()` instead of cryptographically secure RNG
2. **Padding**: Simplified padding implementations
3. **Modes of Operation**: Educational modes like ECB (not secure for production)
4. **Side-Channel Attacks**: No protection against timing attacks

### Best Practices

1. **Always use authenticated encryption** (AES-GCM, ChaCha20-Poly1305)
2. **Never reuse keys** across different contexts
3. **Use proper key derivation functions** (PBKDF2, scrypt, Argon2)
4. **Implement proper key management** and rotation
5. **Stay updated** with current cryptographic standards

## Performance Notes

- **RSA**: Key generation is computationally expensive
- **ECC**: Smaller keys provide equivalent security to RSA
- **AES**: Hardware acceleration available on modern CPUs
- **ChaCha20**: Designed to be fast without hardware acceleration

## Educational Resources

Each algorithm directory contains:

- `algorithm.js` - Main implementation
- `algorithm.test.js` - Unit tests
- `algorithm.example.js` - Production-ready example
- `README.md` - Detailed algorithm information

## Contributing

When contributing to this educational project:

1. Maintain clear, educational code comments
2. Include comprehensive tests
3. Provide examples and documentation
4. Follow the existing code style
5. Add appropriate security warnings

## Further Learning

1. **Books**:

   - "Cryptography Engineering" by Ferguson, Schneier, and Kohno
   - "Applied Cryptography" by Bruce Schneier

2. **Online Courses**:

   - Stanford's Cryptography I on Coursera
   - Dan Boneh's Cryptography courses

3. **Standards**:
   - NIST Cryptographic Standards
   - RFC documents for specific protocols

## License

This project is provided for educational purposes under the MIT license. See the main project LICENSE file for details.
