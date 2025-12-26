/**
 * Unit tests for SHA-256 hashing algorithm
 */

const { SHA256 } = require('./sha256');
const { TestUtils } = require('../testUtils');

function runSHA256Tests() {
    console.log('Running SHA-256 Tests...');
    
    // Test 1: Basic SHA-256 hashing
    TestUtils.runTest('SHA-256', 'Basic hashing', () => {
        const message = 'This is a test message for SHA-256 hashing.';
        const hash = SHA256.hash(message);
        
        TestUtils.assertEqual(typeof hash, 'string', 'Hash should be a string');
        TestUtils.assertEqual(hash.length, 64, 'SHA-256 hash should be 64 characters (32 bytes in hex)');
        
        // Verify that hash is hexadecimal
        const hexRegex = /^[0-9a-f]+$/;
        TestUtils.assert(hexRegex.test(hash), 'Hash should be in hexadecimal format');
    });
    
    // Test 2: SHA-256 with empty string
    TestUtils.runTest('SHA-256', 'Empty string hashing', () => {
        const message = '';
        const hash = SHA256.hash(message);
        const expectedHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
        
        TestUtils.assertEqual(hash, expectedHash, 'Empty string hash should match known test vector');
    });
    
    // Test 3: SHA-256 with single character
    TestUtils.runTest('SHA-256', 'Single character hashing', () => {
        const message = 'a';
        const hash = SHA256.hash(message);
        const expectedHash = 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb';
        
        TestUtils.assertEqual(hash, expectedHash, 'Single character hash should match known test vector');
    });
    
    // Test 4: SHA-256 with known test vector "abc"
    TestUtils.runTest('SHA-256', 'Known test vector "abc"', () => {
        const message = 'abc';
        const hash = SHA256.hash(message);
        const expectedHash = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
        
        TestUtils.assertEqual(hash, expectedHash, '"abc" hash should match known test vector');
    });
    
    // Test 5: SHA-256 with known test vector "The quick brown fox jumps over the lazy dog"
    TestUtils.runTest('SHA-256', 'Known test vector "The quick brown fox jumps over the lazy dog"', () => {
        const message = 'The quick brown fox jumps over the lazy dog';
        const hash = SHA256.hash(message);
        const expectedHash = 'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb7620f65c7b6f1b76b1';
        
        TestUtils.assertEqual(hash, expectedHash, '"The quick brown fox jumps over the lazy dog" hash should match known test vector');
    });
    
    // Test 6: SHA-256 with Uint8Array input
    TestUtils.runTest('SHA-256', 'Uint8Array input', () => {
        const data = new Uint8Array([72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]); // "Hello World"
        const hash = SHA256.hash(data);
        
        TestUtils.assertEqual(typeof hash, 'string', 'Hash should be a string');
        TestUtils.assertEqual(hash.length, 64, 'SHA-256 hash should be 64 characters (32 bytes in hex)');
    });
    
    // Test 7: SHA-256 hash consistency
    TestUtils.runTest('SHA-256', 'Hash consistency', () => {
        const message = 'This is a test message for SHA-256 hashing.';
        const hash1 = SHA256.hash(message);
        const hash2 = SHA256.hash(message);
        
        TestUtils.assertEqual(hash1, hash2, 'Hash should be consistent for the same input');
    });
    
    // Test 8: SHA-256 with different messages
    TestUtils.runTest('SHA-256', 'Different messages produce different hashes', () => {
        const message1 = 'This is message one.';
        const message2 = 'This is message two.';
        
        const hash1 = SHA256.hash(message1);
        const hash2 = SHA256.hash(message2);
        
        TestUtils.assert(hash1 !== hash2, 'Different messages should produce different hashes');
    });
    
    // Test 9: SHA-256 with similar messages
    TestUtils.runTest('SHA-256', 'Similar messages produce very different hashes', () => {
        const message1 = 'This is a test message.';
        const message2 = 'This is a test message!'; // One character difference
        
        const hash1 = SHA256.hash(message1);
        const hash2 = SHA256.hash(message2);
        
        TestUtils.assert(hash1 !== hash2, 'Similar messages should produce different hashes');
        
        // Count different characters
        let diffCount = 0;
        for (let i = 0; i < Math.min(hash1.length, hash2.length); i++) {
            if (hash1[i] !== hash2[i]) {
                diffCount++;
            }
        }
        
        // Avalanche effect: small change should produce many differences
        TestUtils.assert(diffCount > hash1.length / 2, 'Small change should produce many differences in hash');
    });
    
    // Test 10: SHA-256 with special characters
    TestUtils.runTest('SHA-256', 'Special characters hashing', () => {
        const message = 'Special chars: !@#$%^&*()_+-=[]{}|;:,.<>?';
        const hash = SHA256.hash(message);
        
        TestUtils.assertEqual(typeof hash, 'string', 'Hash should be a string');
        TestUtils.assertEqual(hash.length, 64, 'SHA-256 hash should be 64 characters (32 bytes in hex)');
    });
    
    // Test 11: SHA-256 with Unicode characters
    TestUtils.runTest('SHA-256', 'Unicode characters hashing', () => {
        const message = 'Unicode test: 你好, こんにちは, 안녕하세요, Привет, مرحبا';
        const hash = SHA256.hash(message);
        
        TestUtils.assertEqual(typeof hash, 'string', 'Hash should be a string');
        TestUtils.assertEqual(hash.length, 64, 'SHA-256 hash should be 64 characters (32 bytes in hex)');
    });
    
    // Test 12: SHA-256 HMAC with string key and message
    TestUtils.runTest('SHA-256', 'HMAC with string key and message', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1';
        const message = 'This is a message to authenticate';
        const hmac = SHA256.hmac(key, message);
        
        TestUtils.assertEqual(typeof hmac, 'string', 'HMAC should be a string');
        TestUtils.assertEqual(hmac.length, 64, 'HMAC-SHA256 should be 64 characters (32 bytes in hex)');
    });
    
    // Test 13: SHA-256 HMAC consistency
    TestUtils.runTest('SHA-256', 'HMAC consistency', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1';
        const message = 'This is a message to authenticate';
        const hmac1 = SHA256.hmac(key, message);
        const hmac2 = SHA256.hmac(key, message);
        
        TestUtils.assertEqual(hmac1, hmac2, 'HMAC should be consistent for the same input');
    });
    
    // Test 14: SHA-256 HMAC with different keys
    TestUtils.runTest('SHA-256', 'HMAC with different keys', () => {
        const key1 = '63f4945d921d599f27ae4fdf5bada3f1';
        const key2 = 'different-key';
        const message = 'This is a message to authenticate';
        
        const hmac1 = SHA256.hmac(key1, message);
        const hmac2 = SHA256.hmac(key2, message);
        
        TestUtils.assert(hmac1 !== hmac2, 'Different keys should produce different HMACs');
    });
    
    // Test 15: SHA-256 HMAC with different messages
    TestUtils.runTest('SHA-256', 'HMAC with different messages', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1';
        const message1 = 'This is message one.';
        const message2 = 'This is message two.';
        
        const hmac1 = SHA256.hmac(key, message1);
        const hmac2 = SHA256.hmac(key, message2);
        
        TestUtils.assert(hmac1 !== hmac2, 'Different messages should produce different HMACs');
    });
    
    // Test 16: SHA-256 HMAC with Uint8Array inputs
    TestUtils.runTest('SHA-256', 'HMAC with Uint8Array inputs', () => {
        const keyBytes = new TextEncoder().encode('63f4945d921d599f27ae4fdf5bada3f1');
        const messageBytes = new TextEncoder().encode('This is a message to authenticate');
        const hmac = SHA256.hmac(keyBytes, messageBytes);
        
        TestUtils.assertEqual(typeof hmac, 'string', 'HMAC should be a string');
        TestUtils.assertEqual(hmac.length, 64, 'HMAC-SHA256 should be 64 characters (32 bytes in hex)');
    });
    
    // Test 17: SHA-256 hexToBytes and bytesToHex utility functions
    TestUtils.runTest('SHA-256', 'hexToBytes and bytesToHex utilities', () => {
        const originalHex = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
        const bytes = SHA256.hexToBytes(originalHex);
        const hexFromBytes = SHA256.bytesToHex(bytes);
        
        TestUtils.assertEqual(hexFromBytes, originalHex, 'Hex conversion should be reversible');
    });
    
    // Test 18: SHA-256 hexToBytes with invalid input
    TestUtils.runTest('SHA-256', 'hexToBytes with invalid input', () => {
        TestUtils.assertThrows(() => {
            SHA256.hexToBytes('invalid-hex-string'); // Odd length
        }, 'Hex string must have even length');
    });
    
    // Test 19: SHA-256 with very long message
    TestUtils.runTest('SHA-256', 'Very long message hashing', () => {
        const message = 'This is a long message. '.repeat(1000); // 20,000 characters
        const hash = SHA256.hash(message);
        
        TestUtils.assertEqual(typeof hash, 'string', 'Hash should be a string');
        TestUtils.assertEqual(hash.length, 64, 'SHA-256 hash should be 64 characters (32 bytes in hex)');
    });
    
    // Test 20: SHA-256 HMAC verification
    TestUtils.runTest('SHA-256', 'HMAC verification', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1';
        const message = 'This is a message to authenticate';
        const hmac = SHA256.hmac(key, message);
        
        // Verify the HMAC
        const computedHmac = SHA256.hmac(key, message);
        TestUtils.assertEqual(hmac, computedHmac, 'HMAC verification should succeed');
        
        // Verify with wrong key
        const wrongKey = 'wrong-key';
        const wrongHmac = SHA256.hmac(wrongKey, message);
        TestUtils.assert(hmac !== wrongHmac, 'HMAC with wrong key should be different');
        
        // Verify with wrong message
        const wrongMessage = 'This is a wrong message';
        const wrongMessageHmac = SHA256.hmac(key, wrongMessage);
        TestUtils.assert(hmac !== wrongMessageHmac, 'HMAC with wrong message should be different');
    });
    
    console.log('SHA-256 Tests completed.');
}

module.exports = { runSHA256Tests };