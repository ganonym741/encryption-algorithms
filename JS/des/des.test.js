/**
 * Unit tests for DES and TripleDES encryption algorithms
 */

const { DES, TripleDES } = require('./des');
const { TestUtils } = require('../testUtils');

function runDESTests() {
    console.log('Running DES Tests...');
    
    // Test 1: Basic DES encryption and decryption
    TestUtils.runTest('DES', 'Basic encryption and decryption', () => {
        const key = 'bd5a5670'; // 8 bytes
        const des = new DES(key);
        const plaintext = 'This is a test message for DES encryption.';
        
        const encrypted = des.encrypt(plaintext);
        const decrypted = des.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original');
    });
    
    // Test 2: DES encryption with binary data
    TestUtils.runTest('DES', 'Binary data encryption', () => {
        const key = 'bd5a5670'; // 8 bytes
        const des = new DES(key);
        const binaryData = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC]);
        
        const encrypted = des.encrypt(binaryData);
        const decrypted = des.decrypt(encrypted);
        
        TestUtils.assertArraysEqual(decrypted, binaryData, 'Decrypted binary data should match original');
    });
    
    // Test 3: DES empty string encryption
    TestUtils.runTest('DES', 'Empty string encryption', () => {
        const key = 'bd5a5670'; // 8 bytes
        const des = new DES(key);
        const plaintext = '';
        
        const encrypted = des.encrypt(plaintext);
        const decrypted = des.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted empty string should match original');
    });
    
    // Test 4: DES large message encryption (multiple blocks)
    TestUtils.runTest('DES', 'Large message encryption', () => {
        const key = 'bd5a5670'; // 8 bytes
        const des = new DES(key);
        const plaintext = 'This is a much longer message that spans multiple DES blocks. '.repeat(10);
        
        const encrypted = des.encrypt(plaintext);
        const decrypted = des.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted large message should match original');
    });
    
    // Test 5: DES different keys produce different ciphertexts
    TestUtils.runTest('DES', 'Different keys produce different ciphertexts', () => {
        const key1 = 'bd5a5670'; // 8 bytes
        const key2 = 'other8key'; // 8 bytes
        const plaintext = 'This is a test message.';
        
        const des1 = new DES(key1);
        const des2 = new DES(key2);
        
        const encrypted1 = des1.encrypt(plaintext);
        const encrypted2 = des2.encrypt(plaintext);
        
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
    
    // Test 6: DES invalid key size
    TestUtils.runTest('DES', 'Invalid key size', () => {
        TestUtils.assertThrows(() => {
            new DES('short-key'); // Not 8 bytes
        }, 'DES requires an 8-byte key');
    });
    
    // Test 7: DES key as Uint8Array
    TestUtils.runTest('DES', 'Key as Uint8Array', () => {
        const keyBytes = new Uint8Array(8);
        for (let i = 0; i < 8; i++) {
            keyBytes[i] = i;
        }
        
        const des = new DES(keyBytes);
        const plaintext = 'This is a test message.';
        
        const encrypted = des.encrypt(plaintext);
        const decrypted = des.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original');
    });
    
    // Test 8: DES toHex and fromHex utility functions
    TestUtils.runTest('DES', 'toHex and fromHex utilities', () => {
        const key = 'bd5a5670'; // 8 bytes
        const des = new DES(key);
        const plaintext = 'This is a test message.';
        
        const encrypted = des.encrypt(plaintext);
        const encryptedHex = DES.toHex(encrypted);
        const encryptedFromHex = DES.fromHex(encryptedHex);
        
        TestUtils.assertArraysEqual(encrypted, encryptedFromHex, 'Hex conversion should be reversible');
        
        const decrypted = des.decrypt(encryptedFromHex);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original after hex conversion');
    });
    
    // Test 9: DES exact block size
    TestUtils.runTest('DES', 'Exact block size', () => {
        const key = 'bd5a5670'; // 8 bytes
        const des = new DES(key);
        // Create a message exactly 8 bytes (one block)
        const plaintext = '8bytes!!';
        
        TestUtils.assertEqual(plaintext.length, 8, 'Plaintext should be exactly 8 bytes');
        
        const encrypted = des.encrypt(plaintext);
        const decrypted = des.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original');
    });
    
    // Test 10: DES with special characters
    TestUtils.runTest('DES', 'Special characters encryption', () => {
        const key = 'bd5a5670'; // 8 bytes
        const des = new DES(key);
        const plaintext = 'Special chars: !@#$%^&*()_+-=[]{}|;:,.<>?';
        
        const encrypted = des.encrypt(plaintext);
        const decrypted = des.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text with special chars should match original');
    });
    
    console.log('DES Tests completed.');
    
    console.log('Running TripleDES Tests...');
    
    // Test 11: Basic TripleDES encryption and decryption
    TestUtils.runTest('TripleDES', 'Basic encryption and decryption', () => {
        const key1 = 'bd5a5670'; // 8 bytes
        const key2 = 'other8key'; // 8 bytes
        const key3 = 'another8!'; // 8 bytes
        const tripleDes = new TripleDES(key1, key2, key3);
        const plaintext = 'This is a test message for TripleDES encryption.';
        
        const encrypted = tripleDes.encrypt(plaintext);
        const decrypted = tripleDes.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original');
    });
    
    // Test 12: TripleDES with single key (3DES-EDE)
    TestUtils.runTest('TripleDES', 'Single key (3DES-EDE)', () => {
        const key = 'bd5a5670'; // 8 bytes
        const tripleDes = new TripleDES(key); // Single key for all three operations
        const plaintext = 'This is a test message for TripleDES with single key.';
        
        const encrypted = tripleDes.encrypt(plaintext);
        const decrypted = tripleDes.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original');
    });
    
    // Test 13: TripleDES with two keys
    TestUtils.runTest('TripleDES', 'Two keys', () => {
        const key1 = 'bd5a5670'; // 8 bytes
        const key2 = 'other8key'; // 8 bytes
        const tripleDes = new TripleDES(key1, key2); // Third key defaults to key1
        const plaintext = 'This is a test message for TripleDES with two keys.';
        
        const encrypted = tripleDes.encrypt(plaintext);
        const decrypted = tripleDes.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original');
    });
    
    // Test 14: TripleDES encryption with binary data
    TestUtils.runTest('TripleDES', 'Binary data encryption', () => {
        const key1 = 'bd5a5670'; // 8 bytes
        const key2 = 'other8key'; // 8 bytes
        const key3 = 'another8!'; // 8 bytes
        const tripleDes = new TripleDES(key1, key2, key3);
        const binaryData = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC]);
        
        const encrypted = tripleDes.encrypt(binaryData);
        const decrypted = tripleDes.decrypt(encrypted);
        
        TestUtils.assertArraysEqual(decrypted, binaryData, 'Decrypted binary data should match original');
    });
    
    // Test 15: TripleDES empty string encryption
    TestUtils.runTest('TripleDES', 'Empty string encryption', () => {
        const key1 = 'bd5a5670'; // 8 bytes
        const key2 = 'other8key'; // 8 bytes
        const key3 = 'another8!'; // 8 bytes
        const tripleDes = new TripleDES(key1, key2, key3);
        const plaintext = '';
        
        const encrypted = tripleDes.encrypt(plaintext);
        const decrypted = tripleDes.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted empty string should match original');
    });
    
    // Test 16: TripleDES large message encryption
    TestUtils.runTest('TripleDES', 'Large message encryption', () => {
        const key1 = 'bd5a5670'; // 8 bytes
        const key2 = 'other8key'; // 8 bytes
        const key3 = 'another8!'; // 8 bytes
        const tripleDes = new TripleDES(key1, key2, key3);
        const plaintext = 'This is a much longer message that spans multiple TripleDES blocks. '.repeat(10);
        
        const encrypted = tripleDes.encrypt(plaintext);
        const decrypted = tripleDes.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted large message should match original');
    });
    
    // Test 17: TripleDES different keys produce different ciphertexts
    TestUtils.runTest('TripleDES', 'Different keys produce different ciphertexts', () => {
        const key1a = 'bd5a5670'; // 8 bytes
        const key2a = 'other8key'; // 8 bytes
        const key3a = 'another8!'; // 8 bytes
        
        const key1b = 'diff8key!'; // 8 bytes
        const key2b = 'another8k'; // 8 bytes
        const key3b = 'third8key'; // 8 bytes
        
        const plaintext = 'This is a test message.';
        
        const tripleDes1 = new TripleDES(key1a, key2a, key3a);
        const tripleDes2 = new TripleDES(key1b, key2b, key3b);
        
        const encrypted1 = tripleDes1.encrypt(plaintext);
        const encrypted2 = tripleDes2.encrypt(plaintext);
        
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
    
    // Test 18: TripleDES toHex and fromHex utility functions
    TestUtils.runTest('TripleDES', 'toHex and fromHex utilities', () => {
        const key1 = 'bd5a5670'; // 8 bytes
        const key2 = 'other8key'; // 8 bytes
        const key3 = 'another8!'; // 8 bytes
        const tripleDes = new TripleDES(key1, key2, key3);
        const plaintext = 'This is a test message.';
        
        const encrypted = tripleDes.encrypt(plaintext);
        const encryptedHex = TripleDES.toHex(encrypted);
        const encryptedFromHex = TripleDES.fromHex(encryptedHex);
        
        TestUtils.assertArraysEqual(encrypted, encryptedFromHex, 'Hex conversion should be reversible');
        
        const decrypted = tripleDes.decrypt(encryptedFromHex);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original after hex conversion');
    });
    
    // Test 19: TripleDES with special characters
    TestUtils.runTest('TripleDES', 'Special characters encryption', () => {
        const key1 = 'bd5a5670'; // 8 bytes
        const key2 = 'other8key'; // 8 bytes
        const key3 = 'another8!'; // 8 bytes
        const tripleDes = new TripleDES(key1, key2, key3);
        const plaintext = 'Special chars: !@#$%^&*()_+-=[]{}|;:,.<>?';
        
        const encrypted = tripleDes.encrypt(plaintext);
        const decrypted = tripleDes.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text with special chars should match original');
    });
    
    // Test 20: TripleDES with Unicode characters
    TestUtils.runTest('TripleDES', 'Unicode characters encryption', () => {
        const key1 = 'bd5a5670'; // 8 bytes
        const key2 = 'other8key'; // 8 bytes
        const key3 = 'another8!'; // 8 bytes
        const tripleDes = new TripleDES(key1, key2, key3);
        const plaintext = 'Unicode test: 你好, こんにちは, 안녕하세요, Привет, مرحبا';
        
        const encrypted = tripleDes.encrypt(plaintext);
        const decrypted = tripleDes.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted Unicode text should match original');
    });
    
    console.log('TripleDES Tests completed.');
}

module.exports = { runDESTests };