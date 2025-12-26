/**
 * Unit tests for AES encryption algorithm
 */

const { AES } = require('./aes.js');
const { TestUtils } = require('../testUtils.js');

function runAESTests() {
    console.log('Running AES Tests...');
    
    // Test 1: Basic encryption and decryption
    TestUtils.runTest('AES', 'Basic encryption and decryption', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const aes = new AES(key);
        const plaintext = 'This is a test message for AES encryption.';
        
        const encrypted = aes.encrypt(plaintext);
        const decrypted = aes.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original');
    });
    
    // Test 2: Encryption with binary data
    TestUtils.runTest('AES', 'Binary data encryption', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const aes = new AES(key);
        const binaryData = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC]);
        
        const encrypted = aes.encrypt(binaryData);
        const decrypted = aes.decrypt(encrypted);
        
        TestUtils.assertArraysEqual(decrypted, binaryData, 'Decrypted binary data should match original');
    });
    
    // Test 3: Empty string encryption
    TestUtils.runTest('AES', 'Empty string encryption', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const aes = new AES(key);
        const plaintext = '';
        
        const encrypted = aes.encrypt(plaintext);
        const decrypted = aes.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted empty string should match original');
    });
    
    // Test 4: Large message encryption (multiple blocks)
    TestUtils.runTest('AES', 'Large message encryption', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const aes = new AES(key);
        const plaintext = 'This is a much longer message that spans multiple AES blocks. '.repeat(10);
        
        const encrypted = aes.encrypt(plaintext);
        const decrypted = aes.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted large message should match original');
    });
    
    // Test 5: Different keys produce different ciphertexts
    TestUtils.runTest('AES', 'Different keys produce different ciphertexts', () => {
        const key1 = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const key2 = 'other-secret-key-32-bytes-long-123'; // 32 bytes
        const plaintext = 'This is a test message.';
        
        const aes1 = new AES(key1);
        const aes2 = new AES(key2);
        
        const encrypted1 = aes1.encrypt(plaintext);
        const encrypted2 = aes2.encrypt(plaintext);
        
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
    
    // Test 6: Same key and message but different instances
    TestUtils.runTest('AES', 'Same key and message produce same ciphertext', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const plaintext = 'This is a test message.';
        
        const aes1 = new AES(key);
        const aes2 = new AES(key);
        
        const encrypted1 = aes1.encrypt(plaintext);
        const encrypted2 = aes2.encrypt(plaintext);
        
        TestUtils.assertArraysEqual(encrypted1, encrypted2, 'Same key should produce same ciphertext');
    });
    
    // Test 7: Invalid key size
    TestUtils.runTest('AES', 'Invalid key size', () => {
        TestUtils.assertThrows(() => {
            new AES('short-key'); // Less than 32 bytes
        }, 'AES-256 requires a 32-byte key');
    });
    
    // Test 8: Key as Uint8Array
    TestUtils.runTest('AES', 'Key as Uint8Array', () => {
        const keyBytes = new Uint8Array(32);
        for (let i = 0; i < 32; i++) {
            keyBytes[i] = i;
        }
        
        const aes = new AES(keyBytes);
        const plaintext = 'This is a test message.';
        
        const encrypted = aes.encrypt(plaintext);
        const decrypted = aes.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original');
    });
    
    // Test 9: Plaintext as Uint8Array
    TestUtils.runTest('AES', 'Plaintext as Uint8Array', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const aes = new AES(key);
        const plaintextBytes = new TextEncoder().encode('This is a test message.');
        
        const encrypted = aes.encrypt(plaintextBytes);
        const decrypted = aes.decrypt(encrypted);
        
        TestUtils.assertArraysEqual(decrypted, plaintextBytes, 'Decrypted bytes should match original');
    });
    
    // Test 10: Test toHex and fromHex utility functions
    TestUtils.runTest('AES', 'toHex and fromHex utilities', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const aes = new AES(key);
        const plaintext = 'This is a test message.';
        
        const encrypted = aes.encrypt(plaintext);
        const encryptedHex = AES.toHex(encrypted);
        const encryptedFromHex = AES.fromHex(encryptedHex);
        
        TestUtils.assertArraysEqual(encrypted, encryptedFromHex, 'Hex conversion should be reversible');
        
        const decrypted = aes.decrypt(encryptedFromHex);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original after hex conversion');
    });
    
    // Test 11: Test with special characters
    TestUtils.runTest('AES', 'Special characters encryption', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const aes = new AES(key);
        const plaintext = 'Special chars: !@#$%^&*()_+-=[]{}|;:,.<>?';
        
        const encrypted = aes.encrypt(plaintext);
        const decrypted = aes.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text with special chars should match original');
    });
    
    // Test 12: Test with Unicode characters
    TestUtils.runTest('AES', 'Unicode characters encryption', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const aes = new AES(key);
        const plaintext = 'Unicode test: 你好, こんにちは, 안녕하세요, Привет, مرحبا';
        
        const encrypted = aes.encrypt(plaintext);
        const decrypted = aes.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted Unicode text should match original');
    });
    
    // Test 13: Test with exact block size
    TestUtils.runTest('AES', 'Exact block size', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const aes = new AES(key);
        // Create a message exactly 16 bytes (one block)
        const plaintext = 'Exactly16bytes!!';
        
        TestUtils.assertEqual(plaintext.length, 16, 'Plaintext should be exactly 16 bytes');
        
        const encrypted = aes.encrypt(plaintext);
        const decrypted = aes.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original');
    });
    
    // Test 14: Test with one byte less than block size
    TestUtils.runTest('AES', 'One byte less than block size', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const aes = new AES(key);
        // Create a message exactly 15 bytes (one byte less than a block)
        const plaintext = 'Exactly15bytes!';
        
        TestUtils.assertEqual(plaintext.length, 15, 'Plaintext should be exactly 15 bytes');
        
        const encrypted = aes.encrypt(plaintext);
        const decrypted = aes.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original');
    });
    
    // Test 15: Test with one byte more than block size
    TestUtils.runTest('AES', 'One byte more than block size', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const aes = new AES(key);
        // Create a message exactly 17 bytes (one byte more than a block)
        const plaintext = 'Exactly17bytes!!';
        
        TestUtils.assertEqual(plaintext.length, 17, 'Plaintext should be exactly 17 bytes');
        
        const encrypted = aes.encrypt(plaintext);
        const decrypted = aes.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original');
    });
    
    console.log('AES Tests completed.');
}

module.exports = { runAESTests };