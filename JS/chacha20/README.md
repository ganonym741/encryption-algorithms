# ChaCha20 Stream Cipher

## Overview

ChaCha20 is a modern stream cipher designed by Daniel J. Bernstein as a successor to the Salsa20 family. It offers high performance, strong security, and resistance to timing attacks, making it an excellent alternative to AES in many applications.

## Algorithm Details

### Type

- **Stream Cipher**
- **Synchronous Operation**

### Key Features

- **Key Size**: 256 bits (32 bytes)
- **Nonce Size**: 96 bits (12 bytes)
- **Counter Size**: 32 bits
- **Rounds**: 20 (10 double rounds)
- **Block Size**: 512 bits (64 bytes)

### Structure

ChaCha20 generates a keystream by processing a 512-bit block through 20 rounds:

1. **State Initialization** (16 32-bit words):

   - 4 words: Constant "expand 32-byte k"
   - 8 words: 256-bit key
   - 1 word: 32-bit counter
   - 3 words: 96-bit nonce

2. **Quarter Round Function** (applied to 4 words):

   ```
   a += b; d ^= a; d <<<= 16;
   c += d; b ^= c; b <<<= 12;
   a += b; d ^= a; d <<<= 8;
   c += d; b ^= c; b <<<= 7;
   ```

3. **Round Structure**:

   - 10 double rounds (20 total rounds)
   - Each double round: 4 column rounds + 4 diagonal rounds
   - Final state = initial state + working state

4. **Keystream Generation**:
   - Process blocks with incrementing counter
   - XOR plaintext with keystream for encryption
   - XOR ciphertext with keystream for decryption

## Implementation Notes

This educational implementation includes:

- Full 20-round ChaCha20 implementation
- Counter-based operation for message expansion
- Support for arbitrary-length messages
- Hex and binary conversion utilities

### Security Considerations

⚠️ **This implementation uses Math.random() for key/nonce generation in examples.** In production, always use cryptographically secure random number generators and never reuse nonces with the same key.

## Usage

```javascript
const { ChaCha20 } = require("./chacha20.js");

// Generate 256-bit key and 96-bit nonce
const key = "63f4945d921d599f27ae4fdf5bada3f1"; // 32 bytes
const nonce = "my-nonce-12b"; // 12 bytes

// Create ChaCha20 instance
const chacha = new ChaCha20(key, nonce);

// Encrypt data
const plaintext = "This is a secret message";
const encrypted = chacha.encrypt(plaintext);

// Decrypt data
const decrypted = chacha.decrypt(encrypted);
const decryptedText = new TextDecoder().decode(decrypted);

// Verify encryption/decryption
console.log("Success:", plaintext === decryptedText);

// Counter management
chacha.setCounter(0); // Reset counter
chacha.incrementCounter(); // Increment by 1
```

## Pros

1. **High Performance**: Very fast without hardware acceleration
2. **Security**: Strong security margins with 20 rounds
3. **Timing Attack Resistance**: Designed to resist timing attacks
4. **Simple Implementation**: Easier to implement correctly than AES
5. **No Padding Required**: Stream cipher handles any message length

## Cons

1. **Nonce Management**: Critical to never reuse nonces with same key
2. **No Authentication**: Must be combined with MAC or AEAD
3. **Newer Algorithm**: Less extensively analyzed than AES
4. **Limited Standardization**: Fewer standardized implementations
5. **Quantum Vulnerability**: Vulnerable to quantum computers

## Common Use Cases

1. **TLS 1.3**: ChaCha20-Poly1305 AEAD cipher suite
2. **Mobile Devices**: Fast encryption without hardware AES
3. **Network Protocols**: VPNs, secure messaging
4. **Disk Encryption**: Full-disk encryption systems
5. **IoT Devices**: Constrained environment cryptography

## Security Levels

| Configuration        | Security Level | Quantum Resistance | Recommended Use      |
| -------------------- | -------------- | ------------------ | -------------------- |
| ChaCha20 (20 rounds) | Strong         | No                 | Current standard     |
| ChaCha12 (12 rounds) | Good           | No                 | Performance-critical |
| ChaCha8 (8 rounds)   | Basic          | No                 | Legacy systems       |

## Comparison with Other Ciphers

| Algorithm | Type   | Key Size | Speed     | Hardware Support | Security |
| --------- | ------ | -------- | --------- | ---------------- | -------- |
| ChaCha20  | Stream | 256 bits | Very Fast | Not needed       | Strong   |
| AES-256   | Block  | 256 bits | Fast      | AES-NI           | Strong   |
| Salsa20   | Stream | 256 bits | Fast      | Not needed       | Good     |
| RC4       | Stream | 128 bits | Fast      | Not needed       | Broken   |

## Implementation Files

- [`chacha20.js`](./chacha20.js) - Main ChaCha20 implementation
- [`chacha20.test.js`](./chacha20.test.js) - Unit tests
- [`chacha20.demo.js`](./chacha20.demo.js) - Educational demonstration
- [`chacha20.example.js`](./chacha20.example.js) - Production-ready example

## Testing

Run the ChaCha20 tests:

```bash
node chacha20.test.js
```

Or run all tests:

```bash
npm run test:all
```

## Further Reading

1. **RFC 8439**: ChaCha20 and Poly1305 for IETF Protocols
2. **"ChaCha, a variant of Salsa20"** by Daniel J. Bernstein
3. **"The Salsa20 Family of Stream Ciphers"** by Daniel J. Bernstein

## Security Best Practices

1. **Never reuse nonces** with the same key
2. **Use unique nonces** for each message
3. **Combine with authentication** (Poly1305 recommended)
4. **Generate keys with secure random** number generators
5. **Limit counter usage** to prevent overflow
6. **Consider AEAD variants** (ChaCha20-Poly1305)

## Performance Notes

- **Speed**: Very fast on all platforms
- **Memory**: Minimal memory requirements
- **Parallelization**: Limited due to sequential nature
- **Hardware**: No special hardware required
- **Optimization**: SIMD optimizations available

## Real-World Applications

1. **TLS 1.3**: Default cipher suite for many implementations
2. **WireGuard**: Modern VPN protocol
3. **Signal Protocol**: Secure messaging
4. **Linux Kernel**: Available in crypto API
5. **Cloudflare**: Used for web performance

## ChaCha20-Poly1305 AEAD

ChaCha20 is often combined with Poly1305 for authenticated encryption:

1. **Poly1305**: One-time keyed MAC
2. **AEAD Construction**: Authenticated Encryption with Associated Data
3. **Nonce Handling**: 96-bit nonce for both algorithms
4. **Security**: Provides both confidentiality and integrity

## Test Vectors

Known ChaCha20 test vectors for verification:

```
Key: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
Nonce: 000000000000000000000002
Counter: 1
Keystream: e4be7194d6b917f14e02d7d62894a774
```

## Migration Path

When moving from this educational implementation to production:

1. Use Node.js built-in `crypto.createCipheriv('chacha20-poly1305')`
2. Use ChaCha20-Poly1305 for authenticated encryption
3. Implement proper nonce management
4. Add authenticated encryption
5. Consider hardware-specific optimizations

## Standards and RFCs

- **RFC 8439**: ChaCha20 and Poly1305 for IETF Protocols
- **RFC 7539**: ChaCha20 and Poly1305 for IETF Protocols (obsoleted by 8439)
- **RFC 7905**: ChaCha20-Poly1305 Cipher Suites for TLS

## Quantum Computing Impact

ChaCha20 is vulnerable to quantum computers:

- **Grover's Algorithm**: Reduces security from 256 to 128 bits
- **Timeline**: Practical quantum computers may appear in 10-20 years
- **Impact**: Still provides 128-bit security against quantum attacks
- **Recommendation**: Consider post-quantum alternatives for long-term security

## Nonce Management

Proper nonce management is critical for security:

1. **Uniqueness**: Never reuse nonce with same key
2. **Random vs Sequential**: Both approaches possible
3. **Counter Overflow**: Handle 32-bit counter overflow
4. **Key Rotation**: Rotate keys before nonce exhaustion
5. **Storage**: Track used nonces to prevent reuse

## Common Pitfalls

1. **Nonce Reuse**: Catastrophic security failure
2. **Missing Authentication**: Vulnerable to bit-flipping attacks
3. **Weak Random Numbers**: Predictable keys or nonces
4. **Counter Overflow**: Keystream repetition
5. **Implementation Errors**: Side-channel vulnerabilities

## Advanced Topics

1. **XChaCha20**: Extended nonce variant (192-bit nonce)
2. **IETF Variant**: Different counter/nonce arrangement
3. **Hardware Acceleration**: SIMD and GPU implementations
4. **Side-Channel Resistance**: Constant-time implementations
5. **Protocol Integration**: Integration with various protocols

## Design Philosophy

ChaCha20 follows Bernstein's design principles:

1. **Simplicity**: Easy to understand and implement
2. **Security**: Large security margins
3. **Performance**: Fast without special hardware
4. **Resistance**: Resistant to known attacks
5. **Analysis**: Extensive cryptanalysis
