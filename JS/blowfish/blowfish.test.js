/**
 * Unit tests for Blowfish encryption algorithm
 */

const { Blowfish } = require('./blowfish');
const { TestUtils } = require('../testUtils');

function runBlowfishTests() {
    console.log('Running Blowfish Tests...');
    
    // Test 1: Basic Blowfish encryption and decryption
    TestUtils.runTest('Blowfish', 'Basic encryption and decryption', () => {
        const key = '403ba9e2adad1'; // 13 bytes (104 bits)
        const blowfish = new Blowfish(key);
        const plaintext = 'This is a test message for Blowfish encryption.';
        
        const encrypted = blowfish.encrypt(plaintext);
        const decrypted = blowfish.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original');
    });
    
    // Test 2: Blowfish encryption with binary data
    TestUtils.runTest('Blowfish', 'Binary data encryption', () => {
        const key = '403ba9e2adad1'; // 13 bytes (104 bits)
        const blowfish = new Blowfish(key);
        const binaryData = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC]);
        
        const encrypted = blowfish.encrypt(binaryData);
        const decrypted = blowfish.decrypt(encrypted);
        
        TestUtils.assertArraysEqual(decrypted, binaryData, 'Decrypted binary data should match original');
    });
    
    // Test 3: Blowfish empty string encryption
    TestUtils.runTest('Blowfish', 'Empty string encryption', () => {
        const key = '403ba9e2adad1'; // 13 bytes (104 bits)
        const blowfish = new Blowfish(key);
        const plaintext = '';
        
        const encrypted = blowfish.encrypt(plaintext);
        const decrypted = blowfish.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted empty string should match original');
    });
    
    // Test 4: Blowfish large message encryption (multiple blocks)
    TestUtils.runTest('Blowfish', 'Large message encryption', () => {
        const key = '403ba9e2adad1'; // 13 bytes (104 bits)
        const blowfish = new Blowfish(key);
        const plaintext = 'This is a much longer message that spans multiple Blowfish blocks. '.repeat(10);
        
        const encrypted = blowfish.encrypt(plaintext);
        const decrypted = blowfish.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted large message should match original');
    });
    
    // Test 5: Blowfish different keys produce different ciphertexts
    TestUtils.runTest('Blowfish', 'Different keys produce different ciphertexts', () => {
        const key1 = '403ba9e2adad1'; // 13 bytes (104 bits)
        const key2 = 'other-secret-key'; // 16 bytes (128 bits)
        const plaintext = 'This is a test message.';
        
        const blowfish1 = new Blowfish(key1);
        const blowfish2 = new Blowfish(key2);
        
        const encrypted1 = blowfish1.encrypt(plaintext);
        const encrypted2 = blowfish2.encrypt(plaintext);
        
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
    
    // Test 6: Blowfish invalid key size (too short)
    TestUtils.runTest('Blowfish', 'Invalid key size (too short)', () => {
        TestUtils.assertThrows(() => {
            new Blowfish('key'); // 3 bytes (too short)
        }, 'Blowfish key must be between 4 and 56 bytes');
    });
    
    // Test 7: Blowfish invalid key size (too long)
    TestUtils.runTest('Blowfish', 'Invalid key size (too long)', () => {
        TestUtils.assertThrows(() => {
            new Blowfish('a'.repeat(57)); // 57 bytes (too long)
        }, 'Blowfish key must be between 4 and 56 bytes');
    });
    
    // Test 8: Blowfish minimum key size (4 bytes)
    TestUtils.runTest('Blowfish', 'Minimum key size (4 bytes)', () => {
        const key = 'key1'; // 4 bytes (minimum)
        const blowfish = new Blowfish(key);
        const plaintext = 'This is a test message.';
        
        const encrypted = blowfish.encrypt(plaintext);
        const decrypted = blowfish.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original');
    });
    
    // Test 9: Blowfish maximum key size (56 bytes)
    TestUtils.runTest('Blowfish', 'Maximum key size (56 bytes)', () => {
        const key = 'a'.repeat(56); // 56 bytes (maximum)
        const blowfish = new Blowfish(key);
        const plaintext = 'This is a test message.';
        
        const encrypted = blowfish.encrypt(plaintext);
        const decrypted = blowfish.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original');
    });
    
    // Test 10: Blowfish key as Uint8Array
    TestUtils.runTest('Blowfish', 'Key as Uint8Array', () => {
        const keyBytes = new Uint8Array(16);
        for (let i = 0; i < 16; i++) {
            keyBytes[i] = i;
        }
        
        const blowfish = new Blowfish(keyBytes);
        const plaintext = 'This is a test message.';
        
        const encrypted = blowfish.encrypt(plaintext);
        const decrypted = blowfish.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original');
    });
    
    // Test 11: Blowfish plaintext as Uint8Array
    TestUtils.runTest('Blowfish', 'Plaintext as Uint8Array', () => {
        const key = '403ba9e2adad1'; // 13 bytes (104 bits)
        const blowfish = new Blowfish(key);
        const plaintextBytes = new TextEncoder().encode('This is a test message.');
        
        const encrypted = blowfish.encrypt(plaintextBytes);
        const decrypted = blowfish.decrypt(encrypted);
        
        TestUtils.assertArraysEqual(decrypted, plaintextBytes, 'Decrypted bytes should match original');
    });
    
    // Test 12: Blowfish toHex and fromHex utility functions
    TestUtils.runTest('Blowfish', 'toHex and fromHex utilities', () => {
        const key = '403ba9e2adad1'; // 13 bytes (104 bits)
        const blowfish = new Blowfish(key);
        const plaintext = 'This is a test message.';
        
        const encrypted = blowfish.encrypt(plaintext);
        const encryptedHex = Blowfish.toHex(encrypted);
        const encryptedFromHex = Blowfish.fromHex(encryptedHex);
        
        TestUtils.assertArraysEqual(encrypted, encryptedFromHex, 'Hex conversion should be reversible');
        
        const decrypted = blowfish.decrypt(encryptedFromHex);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original after hex conversion');
    });
    
    // Test 13: Blowfish with special characters
    TestUtils.runTest('Blowfish', 'Special characters encryption', () => {
        const key = '403ba9e2adad1'; // 13 bytes (104 bits)
        const blowfish = new Blowfish(key);
        const plaintext = 'Special chars: !@#$%^&*()_+-=[]{}|;:,.<>?';
        
        const encrypted = blowfish.encrypt(plaintext);
        const decrypted = blowfish.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text with special chars should match original');
    });
    
    // Test 14: Blowfish with Unicode characters
    TestUtils.runTest('Blowfish', 'Unicode characters encryption', () => {
        const key = '403ba9e2adad1'; // 13 bytes (104 bits)
        const blowfish = new Blowfish(key);
        const plaintext = 'Unicode test: 你好, こんにちは, 안녕하세요, Привет, مرحبا';
        
        const encrypted = blowfish.encrypt(plaintext);
        const decrypted = blowfish.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted Unicode text should match original');
    });
    
    // Test 15: Blowfish exact block size
    TestUtils.runTest('Blowfish', 'Exact block size', () => {
        const key = '403ba9e2adad1'; // 13 bytes (104 bits)
        const blowfish = new Blowfish(key);
        // Create a message exactly 8 bytes (one block)
        const plaintext = '8bytes!!';
        
        TestUtils.assertEqual(plaintext.length, 8, 'Plaintext should be exactly 8 bytes');
        
        const encrypted = blowfish.encrypt(plaintext);
        const decrypted = blowfish.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original');
    });
    
    // Test 16: Blowfish one byte less than block size
    TestUtils.runTest('Blowfish', 'One byte less than block size', () => {
        const key = '403ba9e2adad1'; // 13 bytes (104 bits)
        const blowfish = new Blowfish(key);
        // Create a message exactly 7 bytes (one byte less than a block)
        const plaintext = '7bytes!';
        
        TestUtils.assertEqual(plaintext.length, 7, 'Plaintext should be exactly 7 bytes');
        
        const encrypted = blowfish.encrypt(plaintext);
        const decrypted = blowfish.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original');
    });
    
    // Test 17: Blowfish one byte more than block size
    TestUtils.runTest('Blowfish', 'One byte more than block size', () => {
        const key = '403ba9e2adad1'; // 13 bytes (104 bits)
        const blowfish = new Blowfish(key);
        // Create a message exactly 9 bytes (one byte more than a block)
        const plaintext = '9bytes!!!';
        
        TestUtils.assertEqual(plaintext.length, 9, 'Plaintext should be exactly 9 bytes');
        
        const encrypted = blowfish.encrypt(plaintext);
        const decrypted = blowfish.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original');
    });
    
    // Test 18: Blowfish with 32-bit key
    TestUtils.runTest('Blowfish', '32-bit key', () => {
        const key = '12345678'; // 8 bytes (64 bits)
        const blowfish = new Blowfish(key);
        const plaintext = 'This is a test message with a 64-bit key.';
        
        const encrypted = blowfish.encrypt(plaintext);
        const decrypted = blowfish.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original');
    });
    
    // Test 19: Blowfish with 448-bit key
    TestUtils.runTest('Blowfish', '448-bit key', () => {
        const key = 'a'.repeat(56); // 56 bytes (448 bits)
        const blowfish = new Blowfish(key);
        const plaintext = 'This is a test message with a 448-bit key.';
        
        const encrypted = blowfish.encrypt(plaintext);
        const decrypted = blowfish.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original');
    });
    
    // Test 20: Blowfish same key and message but different instances
    TestUtils.runTest('Blowfish', 'Same key and message produce same ciphertext', () => {
        const key = '403ba9e2adad1'; // 13 bytes (104 bits)
        const plaintext = 'This is a test message.';
        
        const blowfish1 = new Blowfish(key);
        const blowfish2 = new Blowfish(key);
        
        const encrypted1 = blowfish1.encrypt(plaintext);
        const encrypted2 = blowfish2.encrypt(plaintext);
        
        TestUtils.assertArraysEqual(encrypted1, encrypted2, 'Same key should produce same ciphertext');
    });
    
    console.log('Blowfish Tests completed.');
}

module.exports = { runBlowfishTests };