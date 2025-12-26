/**
 * Unit tests for RSA encryption and signing algorithm
 */

const { RSA } = require('./rsa');
const { TestUtils } = require('../testUtils');

function runRSATests() {
    console.log('Running RSA Tests...');
    
    // Test 1: Basic RSA encryption and decryption
    TestUtils.runTest('RSA', 'Basic encryption and decryption', () => {
        const rsa = new RSA(512); // 512 bits for faster testing
        const plaintext = 'This is a test message for RSA encryption.';
        
        const encrypted = rsa.encrypt(plaintext);
        const decrypted = rsa.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original');
    });
    
    // Test 2: RSA encryption with binary data
    TestUtils.runTest('RSA', 'Binary data encryption', () => {
        const rsa = new RSA(512);
        const binaryData = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC]);
        
        const encrypted = rsa.encrypt(binaryData);
        const decrypted = rsa.decrypt(encrypted);
        
        TestUtils.assertArraysEqual(decrypted, binaryData, 'Decrypted binary data should match original');
    });
    
    // Test 3: RSA empty string encryption
    TestUtils.runTest('RSA', 'Empty string encryption', () => {
        const rsa = new RSA(512);
        const plaintext = '';
        
        const encrypted = rsa.encrypt(plaintext);
        const decrypted = rsa.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted empty string should match original');
    });
    
    // Test 4: RSA different key sizes
    TestUtils.runTest('RSA', 'Different key sizes', () => {
        const rsa512 = new RSA(512);
        const rsa1024 = new RSA(1024);
        const plaintext = 'This is a test message.';
        
        const encrypted512 = rsa512.encrypt(plaintext);
        const decrypted512 = rsa512.decrypt(encrypted512);
        const decryptedText512 = new TextDecoder().decode(decrypted512);
        
        const encrypted1024 = rsa1024.encrypt(plaintext);
        const decrypted1024 = rsa1024.decrypt(encrypted1024);
        const decryptedText1024 = new TextDecoder().decode(decrypted1024);
        
        TestUtils.assertEqual(decryptedText512, plaintext, '512-bit RSA decryption should match original');
        TestUtils.assertEqual(decryptedText1024, plaintext, '1024-bit RSA decryption should match original');
        
        // Ciphertexts should be different due to different keys
        let ciphertextsMatch = true;
        if (encrypted512.length !== encrypted1024.length) {
            ciphertextsMatch = false;
        } else {
            for (let i = 0; i < encrypted512.length; i++) {
                if (encrypted512[i] !== encrypted1024[i]) {
                    ciphertextsMatch = false;
                    break;
                }
            }
        }
        
        TestUtils.assert(!ciphertextsMatch, 'Different key sizes should produce different ciphertexts');
    });
    
    // Test 5: RSA key size too small
    TestUtils.runTest('RSA', 'Key size too small', () => {
        TestUtils.assertThrows(() => {
            new RSA(256); // Too small for security
        }, 'RSA key size must be at least 512 bits for security');
    });
    
    // Test 6: RSA get public and private keys
    TestUtils.runTest('RSA', 'Get public and private keys', () => {
        const rsa = new RSA(512);
        
        const publicKey = rsa.getPublicKey();
        const privateKey = rsa.getPrivateKey();
        
        TestUtils.assert(!!publicKey.n && !!publicKey.e, 'Public key should have n and e values');
        TestUtils.assert(!!privateKey.n && !!privateKey.e && !!privateKey.d && !!privateKey.p && !!privateKey.q, 'Private key should have n, e, d, p, and q values');
        
        // Verify that public key values are strings
        TestUtils.assertEqual(typeof publicKey.n, 'string', 'Public key n should be a string');
        TestUtils.assertEqual(typeof publicKey.e, 'string', 'Public key e should be a string');
        
        // Verify that private key values are strings
        TestUtils.assertEqual(typeof privateKey.n, 'string', 'Private key n should be a string');
        TestUtils.assertEqual(typeof privateKey.e, 'string', 'Private key e should be a string');
        TestUtils.assertEqual(typeof privateKey.d, 'string', 'Private key d should be a string');
        TestUtils.assertEqual(typeof privateKey.p, 'string', 'Private key p should be a string');
        TestUtils.assertEqual(typeof privateKey.q, 'string', 'Private key q should be a string');
    });
    
    // Test 7: RSA from public key
    TestUtils.runTest('RSA', 'Create from public key', () => {
        const rsa1 = new RSA(512);
        const plaintext = 'This is a test message.';
        
        const publicKey = rsa1.getPublicKey();
        const rsa2 = RSA.fromPublicKey(publicKey);
        
        const encrypted = rsa2.encrypt(plaintext);
        const decrypted = rsa1.decrypt(encrypted); // Decrypt with original instance that has private key
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decryption with imported public key should work');
    });
    
    // Test 8: RSA from private key
    TestUtils.runTest('RSA', 'Create from private key', () => {
        const rsa1 = new RSA(512);
        const plaintext = 'This is a test message.';
        
        const privateKey = rsa1.getPrivateKey();
        const rsa2 = RSA.fromPrivateKey(privateKey);
        
        const encrypted = rsa2.encrypt(plaintext);
        const decrypted = rsa2.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Encryption and decryption with imported private key should work');
    });
    
    // Test 9: RSA message signing and verification
    TestUtils.runTest('RSA', 'Message signing and verification', () => {
        const rsa = new RSA(512);
        const message = 'This is a message to be signed using RSA.';
        
        const signature = rsa.sign(message);
        const isValid = rsa.verify(message, signature);
        
        TestUtils.assert(isValid, 'Signature should be valid for original message');
    });
    
    // Test 10: RSA signature verification with tampered message
    TestUtils.runTest('RSA', 'Signature verification with tampered message', () => {
        const rsa = new RSA(512);
        const message = 'This is a message to be signed using RSA.';
        const tamperedMessage = 'This is a tampered message.';
        
        const signature = rsa.sign(message);
        const isValid = rsa.verify(tamperedMessage, signature);
        
        TestUtils.assert(!isValid, 'Signature should be invalid for tampered message');
    });
    
    // Test 11: RSA toHex and fromHex utility functions
    TestUtils.runTest('RSA', 'toHex and fromHex utilities', () => {
        const rsa = new RSA(512);
        const plaintext = 'This is a test message.';
        
        const encrypted = rsa.encrypt(plaintext);
        const encryptedHex = RSA.toHex(encrypted);
        const encryptedFromHex = RSA.fromHex(encryptedHex);
        
        TestUtils.assertArraysEqual(encrypted, encryptedFromHex, 'Hex conversion should be reversible');
        
        const decrypted = rsa.decrypt(encryptedFromHex);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original after hex conversion');
    });
    
    // Test 12: RSA with special characters
    TestUtils.runTest('RSA', 'Special characters encryption', () => {
        const rsa = new RSA(512);
        const plaintext = 'Special chars: !@#$%^&*()_+-=[]{}|;:,.<>?';
        
        const encrypted = rsa.encrypt(plaintext);
        const decrypted = rsa.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text with special chars should match original');
    });
    
    // Test 13: RSA with Unicode characters
    TestUtils.runTest('RSA', 'Unicode characters encryption', () => {
        const rsa = new RSA(512);
        const plaintext = 'Unicode test: 你好, こんにちは, 안녕하세요, Привет, مرحبا';
        
        const encrypted = rsa.encrypt(plaintext);
        const decrypted = rsa.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted Unicode text should match original');
    });
    
    // Test 14: RSA message too large
    TestUtils.runTest('RSA', 'Message too large', () => {
        const rsa = new RSA(512);
        // Create a message that's too large for 512-bit RSA
        const plaintext = 'a'.repeat(100);
        
        TestUtils.assertThrows(() => {
            rsa.encrypt(plaintext);
        }, 'Message too large for RSA');
    });
    
    // Test 15: RSA same message encrypted multiple times
    TestUtils.runTest('RSA', 'Same message encrypted multiple times', () => {
        const rsa = new RSA(512);
        const plaintext = 'This is a test message.';
        
        const encrypted1 = rsa.encrypt(plaintext);
        const encrypted2 = rsa.encrypt(plaintext);
        
        // With proper padding, same message should produce different ciphertexts
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
        
        TestUtils.assert(!ciphertextsMatch, 'Same message should produce different ciphertexts with proper padding');
    });
    
    // Test 16: RSA different instances with same key
    TestUtils.runTest('RSA', 'Different instances with same key', () => {
        const rsa1 = new RSA(512);
        const rsa2 = new RSA(512);
        const plaintext = 'This is a test message.';
        
        const encrypted1 = rsa1.encrypt(plaintext);
        const encrypted2 = rsa2.encrypt(plaintext);
        
        TestUtils.assertArraysEqual(encrypted1, encrypted2, 'Same key should produce same ciphertext');
    });
    
    // Test 17: RSA signature as bytes
    TestUtils.runTest('RSA', 'Signature as bytes', () => {
        const rsa = new RSA(512);
        const message = 'This is a message to be signed using RSA.';
        
        const signature = rsa.sign(message);
        TestUtils.assert(signature.length > 0, 'Signature should not be empty');
    });
    
    // Test 18: RSA key export and import round trip
    TestUtils.runTest('RSA', 'Key export and import round trip', () => {
        const rsa1 = new RSA(512);
        const plaintext = 'This is a test message.';
        
        const publicKey = rsa1.getPublicKey();
        const privateKey = rsa1.getPrivateKey();
        const rsa2 = RSA.fromPublicKey(publicKey);
        const rsa3 = RSA.fromPrivateKey(privateKey);
        
        const encryptedWithPublic = rsa2.encrypt(plaintext);
        const decryptedWithPrivate = rsa1.decrypt(encryptedWithPublic);
        const decryptedTextWithPrivate = new TextDecoder().decode(decryptedWithPrivate);
        
        TestUtils.assertEqual(decryptedTextWithPrivate, plaintext, 'Public key import/export should work');
    });
    
    // Test 19: RSA with 2048-bit key
    TestUtils.runTest('RSA', '2048-bit key', () => {
        const rsa = new RSA(2048); // Production-grade key size
        const plaintext = 'This is a test message with a 2048-bit key.';
        
        const encrypted = rsa.encrypt(plaintext);
        const decrypted = rsa.decrypt(encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original');
    });
    
    // Test 20: RSA plaintext as Uint8Array
    TestUtils.runTest('RSA', 'Plaintext as Uint8Array', () => {
        const rsa = new RSA(512);
        const plaintextBytes = new TextEncoder().encode('This is a test message.');
        
        const encrypted = rsa.encrypt(plaintextBytes);
        const decrypted = rsa.decrypt(encrypted);
        
        TestUtils.assertArraysEqual(decrypted, plaintextBytes, 'Decrypted bytes should match original');
    });
    
    console.log('RSA Tests completed.');
}

module.exports = { runRSATests };