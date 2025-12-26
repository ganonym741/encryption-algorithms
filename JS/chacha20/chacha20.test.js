/**
 * Unit tests for ChaCha20 stream cipher
 */

const { ChaCha20 } = require('./chacha20');
const { TestUtils } = require('../testUtils');

function runChaCha20Tests() {
    console.log('Running ChaCha20 Tests...');
    
    // Test 1: Basic ChaCha20 encryption and decryption
    TestUtils.runTest('ChaCha20', 'Basic encryption and decryption', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const nonce = '69f71e2ae0c1'; // 12 bytes
        const chacha = new ChaCha20(key, nonce);
        const plaintext = 'This is a test message for ChaCha20 encryption.';
        
        const encrypted = chacha.encrypt(plaintext);
        const decrypted = chacha.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original');
    });
    
    // Test 2: ChaCha20 encryption with binary data
    TestUtils.runTest('ChaCha20', 'Binary data encryption', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const nonce = '69f71e2ae0c1'; // 12 bytes
        const chacha = new ChaCha20(key, nonce);
        const binaryData = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC]);
        
        const encrypted = chacha.encrypt(binaryData);
        const decrypted = chacha.decrypt(encrypted);
        
        TestUtils.assertArraysEqual(decrypted, binaryData, 'Decrypted binary data should match original');
    });
    
    // Test 3: ChaCha20 empty string encryption
    TestUtils.runTest('ChaCha20', 'Empty string encryption', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const nonce = '69f71e2ae0c1'; // 12 bytes
        const chacha = new ChaCha20(key, nonce);
        const plaintext = '';
        
        const encrypted = chacha.encrypt(plaintext);
        const decrypted = chacha.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted empty string should match original');
    });
    
    // Test 4: ChaCha20 large message encryption (multiple blocks)
    TestUtils.runTest('ChaCha20', 'Large message encryption', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const nonce = '69f71e2ae0c1'; // 12 bytes
        const chacha = new ChaCha20(key, nonce);
        const plaintext = 'This is a much longer message that spans multiple ChaCha20 blocks. '.repeat(10);
        
        const encrypted = chacha.encrypt(plaintext);
        const decrypted = chacha.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted large message should match original');
    });
    
    // Test 5: ChaCha20 different keys produce different ciphertexts
    TestUtils.runTest('ChaCha20', 'Different keys produce different ciphertexts', () => {
        const key1 = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const key2 = 'other-secret-key-32-bytes-long-123'; // 32 bytes
        const nonce = '69f71e2ae0c1'; // 12 bytes
        
        const chacha1 = new ChaCha20(key1, nonce);
        const chacha2 = new ChaCha20(key2, nonce);
        
        const plaintext = 'This is a test message.';
        const encrypted1 = chacha1.encrypt(plaintext);
        const encrypted2 = chacha2.encrypt(plaintext);
        
        // Ciphertexts should be different
        let ciphertextsMatch = true;
        if (encrypted1.length !== encrypted2.length) {
            ciphertextsMatch = false;
        } else {
            for (let i = 0; i < encrypted1.length; i++) {
                if (encrypted1[i] !== encrypted2[i]) {
                    ciphertextsMatch = false;
                    break;
                }
            }
        }
        
        TestUtils.assert(!ciphertextsMatch, 'Different keys should produce different ciphertexts');
    });
    
    // Test 6: ChaCha20 different nonces produce different ciphertexts
    TestUtils.runTest('ChaCha20', 'Different nonces produce different ciphertexts', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const nonce1 = '69f71e2ae0c1'; // 12 bytes
        const nonce2 = 'other-nonce-12'; // 12 bytes
        
        const chacha1 = new ChaCha20(key, nonce1);
        const chacha2 = new ChaCha20(key, nonce2);
        
        const plaintext = 'This is a test message.';
        const encrypted1 = chacha1.encrypt(plaintext);
        const encrypted2 = chacha2.encrypt(plaintext);
        
        // Ciphertexts should be different
        let ciphertextsMatch = true;
        if (encrypted1.length !== encrypted2.length) {
            ciphertextsMatch = false;
        } else {
            for (let i = 0; i < encrypted1.length; i++) {
                if (encrypted1[i] !== encrypted2[i]) {
                    ciphertextsMatch = false;
                    break;
                }
            }
        }
        
        TestUtils.assert(!ciphertextsMatch, 'Different nonces should produce different ciphertexts');
    });
    
    // Test 7: ChaCha20 invalid key size
    TestUtils.runTest('ChaCha20', 'Invalid key size', () => {
        const nonce = '69f71e2ae0c1'; // 12 bytes
        
        TestUtils.assertThrows(() => {
            new ChaCha20('short-key', nonce); // Less than 32 bytes
        }, 'ChaCha20 key must be 32 bytes');
    });
    
    // Test 8: ChaCha20 invalid nonce size
    TestUtils.runTest('ChaCha20', 'Invalid nonce size', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        
        TestUtils.assertThrows(() => {
            new ChaCha20(key, 'short-nonce'); // Less than 12 bytes
        }, 'ChaCha20 nonce must be 12 bytes');
    });
    
    // Test 9: ChaCha20 key and nonce as Uint8Array
    TestUtils.runTest('ChaCha20', 'Key and nonce as Uint8Array', () => {
        const keyBytes = new Uint8Array(32);
        for (let i = 0; i < 32; i++) {
            keyBytes[i] = i;
        }
        
        const nonceBytes = new Uint8Array(12);
        for (let i = 0; i < 12; i++) {
            nonceBytes[i] = i;
        }
        
        const chacha = new ChaCha20(keyBytes, nonceBytes);
        const plaintext = 'This is a test message.';
        
        const encrypted = chacha.encrypt(plaintext);
        const decrypted = chacha.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original');
    });
    
    // Test 10: ChaCha20 plaintext as Uint8Array
    TestUtils.runTest('ChaCha20', 'Plaintext as Uint8Array', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const nonce = '69f71e2ae0c1'; // 12 bytes
        const chacha = new ChaCha20(key, nonce);
        const plaintextBytes = new TextEncoder().encode('This is a test message.');
        
        const encrypted = chacha.encrypt(plaintextBytes);
        const decrypted = chacha.decrypt(encrypted);
        
        TestUtils.assertArraysEqual(decrypted, plaintextBytes, 'Decrypted bytes should match original');
    });
    
    // Test 11: ChaCha20 toHex and fromHex utility functions
    TestUtils.runTest('ChaCha20', 'toHex and fromHex utilities', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const nonce = '69f71e2ae0c1'; // 12 bytes
        const chacha = new ChaCha20(key, nonce);
        const plaintext = 'This is a test message.';
        
        const encrypted = chacha.encrypt(plaintext);
        const encryptedHex = ChaCha20.toHex(encrypted);
        const encryptedFromHex = ChaCha20.fromHex(encryptedHex);
        
        TestUtils.assertArraysEqual(encrypted, encryptedFromHex, 'Hex conversion should be reversible');
        
        const decrypted = chacha.decrypt(encryptedFromHex);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original after hex conversion');
    });
    
    // Test 12: ChaCha20 with special characters
    TestUtils.runTest('ChaCha20', 'Special characters encryption', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const nonce = '69f71e2ae0c1'; // 12 bytes
        const chacha = new ChaCha20(key, nonce);
        const plaintext = 'Special chars: !@#$%^&*()_+-=[]{}|;:,.<>?';
        
        const encrypted = chacha.encrypt(plaintext);
        const decrypted = chacha.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text with special chars should match original');
    });
    
    // Test 13: ChaCha20 with Unicode characters
    TestUtils.runTest('ChaCha20', 'Unicode characters encryption', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const nonce = '69f71e2ae0c1'; // 12 bytes
        const chacha = new ChaCha20(key, nonce);
        const plaintext = 'Unicode test: 你好, こんにちは, 안녕하세요, Привет, مرحبا';
        
        const encrypted = chacha.encrypt(plaintext);
        const decrypted = chacha.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted Unicode text should match original');
    });
    
    // Test 14: ChaCha20 counter operations
    TestUtils.runTest('ChaCha20', 'Counter operations', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const nonce = '69f71e2ae0c1'; // 12 bytes
        const chacha = new ChaCha20(key, nonce);
        
        // Test initial counter
        TestUtils.assertEqual(chacha.getCounter(), 0, 'Initial counter should be 0');
        
        // Test set counter
        chacha.setCounter(5);
        TestUtils.assertEqual(chacha.getCounter(), 5, 'Counter should be set to 5');
        
        // Test increment counter
        chacha.incrementCounter();
        TestUtils.assertEqual(chacha.getCounter(), 6, 'Counter should increment to 6');
        
        // Test encryption with different counters
        chacha.setCounter(0);
        const encrypted1 = chacha.encrypt('Message 1');
        
        chacha.setCounter(0);
        const encrypted2 = chacha.encrypt('Message 1');
        
        TestUtils.assertArraysEqual(encrypted1, encrypted2, 'Same counter should produce same ciphertext');
        
        chacha.incrementCounter();
        const encrypted3 = chacha.encrypt('Message 2');
        
        // Different counter should produce different ciphertext
        let ciphertextsMatch = true;
        if (encrypted1.length !== encrypted3.length) {
            ciphertextsMatch = false;
        } else {
            for (let i = 0; i < encrypted1.length; i++) {
                if (encrypted1[i] !== encrypted3[i]) {
                    ciphertextsMatch = false;
                    break;
                }
            }
        }
        
        TestUtils.assert(!ciphertextsMatch, 'Different counter should produce different ciphertext');
    });
    
    // Test 15: ChaCha20 exact block size
    TestUtils.runTest('ChaCha20', 'Exact block size', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const nonce = '69f71e2ae0c1'; // 12 bytes
        const chacha = new ChaCha20(key, nonce);
        // Create a message exactly 64 bytes (one block)
        const plaintext = 'a'.repeat(64);
        
        TestUtils.assertEqual(plaintext.length, 64, 'Plaintext should be exactly 64 bytes');
        
        const encrypted = chacha.encrypt(plaintext);
        const decrypted = chacha.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original');
    });
    
    // Test 16: ChaCha20 one byte less than block size
    TestUtils.runTest('ChaCha20', 'One byte less than block size', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const nonce = '69f71e2ae0c1'; // 12 bytes
        const chacha = new ChaCha20(key, nonce);
        // Create a message exactly 63 bytes (one byte less than a block)
        const plaintext = 'a'.repeat(63);
        
        TestUtils.assertEqual(plaintext.length, 63, 'Plaintext should be exactly 63 bytes');
        
        const encrypted = chacha.encrypt(plaintext);
        const decrypted = chacha.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original');
    });
    
    // Test 17: ChaCha20 one byte more than block size
    TestUtils.runTest('ChaCha20', 'One byte more than block size', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const nonce = '69f71e2ae0c1'; // 12 bytes
        const chacha = new ChaCha20(key, nonce);
        // Create a message exactly 65 bytes (one byte more than a block)
        const plaintext = 'a'.repeat(65);
        
        TestUtils.assertEqual(plaintext.length, 65, 'Plaintext should be exactly 65 bytes');
        
        const encrypted = chacha.encrypt(plaintext);
        const decrypted = chacha.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original');
    });
    
    // Test 18: ChaCha20 same key and nonce but different instances
    TestUtils.runTest('ChaCha20', 'Same key and nonce produce same ciphertext', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const nonce = '69f71e2ae0c1'; // 12 bytes
        const plaintext = 'This is a test message.';
        
        const chacha1 = new ChaCha20(key, nonce);
        const chacha2 = new ChaCha20(key, nonce);
        
        const encrypted1 = chacha1.encrypt(plaintext);
        const encrypted2 = chacha2.encrypt(plaintext);
        
        TestUtils.assertArraysEqual(encrypted1, encrypted2, 'Same key and nonce should produce same ciphertext');
    });
    
    // Test 19: ChaCha20 with custom counter
    TestUtils.runTest('ChaCha20', 'Custom counter', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const nonce = '69f71e2ae0c1'; // 12 bytes
        const chacha1 = new ChaCha20(key, nonce, 0); // Counter 0
        const chacha2 = new ChaCha20(key, nonce, 5); // Counter 5
        
        const plaintext = 'This is a test message.';
        
        const encrypted1 = chacha1.encrypt(plaintext);
        const encrypted2 = chacha2.encrypt(plaintext);
        
        // Different counters should produce different ciphertexts
        let ciphertextsMatch = true;
        if (encrypted1.length !== encrypted2.length) {
            ciphertextsMatch = false;
        } else {
            for (let i = 0; i < encrypted1.length; i++) {
                if (encrypted1[i] !== encrypted2[i]) {
                    ciphertextsMatch = false;
                    break;
                }
            }
        }
        
        TestUtils.assert(!ciphertextsMatch, 'Different counters should produce different ciphertexts');
    });
    
    // Test 20: ChaCha20 crypt method
    TestUtils.runTest('ChaCha20', 'crypt method', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const nonce = '69f71e2ae0c1'; // 12 bytes
        const chacha = new ChaCha20(key, nonce);
        const plaintext = 'This is a test message.';
        
        const encrypted1 = chacha.encrypt(plaintext);
        const encrypted2 = chacha.crypt(plaintext);
        
        TestUtils.assertArraysEqual(encrypted1, encrypted2, 'encrypt and crypt should produce same result');
        
        const decrypted1 = chacha.decrypt(encrypted1);
        const decrypted2 = chacha.crypt(encrypted1);
        
        TestUtils.assertArraysEqual(decrypted1, decrypted2, 'decrypt and crypt should produce same result');
    });
    
    console.log('ChaCha20 Tests completed.');
}

module.exports = { runChaCha20Tests };