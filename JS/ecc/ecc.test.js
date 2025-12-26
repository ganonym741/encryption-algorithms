/**
 * Unit tests for ECC (Elliptic Curve Cryptography) algorithm
 */

const { ECC } = require('./ecc');
const { TestUtils } = require('../testUtils');

function runECCTests() {
    console.log('Running ECC Tests...');
    
    // Test 1: Basic ECC key generation
    TestUtils.runTest('ECC', 'Basic key generation', () => {
        const ecc = new ECC();
        
        const privateKey = ecc.getPrivateKey();
        const publicKey = ecc.getPublicKey();
        
        TestUtils.assert(privateKey > 1n && privateKey < ECC.hexToBigInt('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'), 'Private key should be in valid range');
        TestUtils.assert(publicKey.x > 0n && publicKey.y > 0n, 'Public key should have valid coordinates');
    });
    
    // Test 2: ECC with custom private key
    TestUtils.runTest('ECC', 'Custom private key', () => {
        const customPrivateKey = ECC.hexToBigInt('123456789ABCDEF');
        const ecc = new ECC(customPrivateKey);
        
        const privateKey = ecc.getPrivateKey();
        const publicKey = ecc.getPublicKey();
        
        TestUtils.assertEqual(privateKey, customPrivateKey, 'Private key should match input');
        TestUtils.assert(publicKey.x > 0n && publicKey.y > 0n, 'Public key should have valid coordinates');
    });
    
    // Test 3: ECC public key calculation
    TestUtils.runTest('ECC', 'Public key calculation', () => {
        const privateKey = ECC.hexToBigInt('123456789ABCDEF');
        const ecc = new ECC(privateKey);
        
        const publicKey = ecc.getPublicKey();
        
        // Public key should be G * private key
        // We can't easily verify this without implementing scalar multiplication again,
        // but we can at least check that public key is on curve
        // y^2 = x^3 + 7 (mod p) for secp256k1
        const x = publicKey.x;
        const y = publicKey.y;
        const p = ECC.hexToBigInt('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
        
        const leftSide = (y * y) % p;
        const rightSide = (x * x * x + 7n) % p;
        
        TestUtils.assertEqual(leftSide, rightSide, 'Public key should be on curve');
    });
    
    // Test 4: ECC compressed public key
    TestUtils.runTest('ECC', 'Compressed public key', () => {
        const ecc = new ECC();
        
        const compressedKey = ecc.getCompressedPublicKey();
        
        TestUtils.assertEqual(compressedKey.length, 33, 'Compressed public key should be 33 bytes');
        TestUtils.assert(compressedKey[0] === 0x02 || compressedKey[0] === 0x03, 'Compressed public key should start with 0x02 or 0x03');
    });
    
    // Test 5: ECC message signing
    TestUtils.runTest('ECC', 'Message signing', () => {
        const ecc = new ECC();
        const message = 'This is a message to be signed using ECDSA.';
        
        const signature = ecc.sign(message);
        
        TestUtils.assert(signature.r > 0n && signature.s > 0n, 'Signature should have valid r and s values');
        TestUtils.assert(signature.r < ECC.hexToBigInt('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'), 'Signature r should be in valid range');
        TestUtils.assert(signature.s < ECC.hexToBigInt('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'), 'Signature s should be in valid range');
    });
    
    // Test 6: ECC signature verification
    TestUtils.runTest('ECC', 'Signature verification', () => {
        const ecc = new ECC();
        const message = 'This is a message to be signed using ECDSA.';
        
        const signature = ecc.sign(message);
        const isValid = ecc.verify(message, signature, ecc.getPublicKey());
        
        TestUtils.assert(isValid, 'Signature should be valid for original message');
    });
    
    // Test 7: ECC signature verification with tampered message
    TestUtils.runTest('ECC', 'Signature verification with tampered message', () => {
        const ecc = new ECC();
        const message = 'This is a message to be signed using ECDSA.';
        const tamperedMessage = 'This is a tampered message.';
        
        const signature = ecc.sign(message);
        const isValid = ecc.verify(tamperedMessage, signature, ecc.getPublicKey());
        
        TestUtils.assert(!isValid, 'Signature should be invalid for tampered message');
    });
    
    // Test 8: ECC signature verification with wrong public key
    TestUtils.runTest('ECC', 'Signature verification with wrong public key', () => {
        const ecc1 = new ECC();
        const ecc2 = new ECC();
        const message = 'This is a message to be signed using ECDSA.';
        
        const signature = ecc1.sign(message);
        const isValid = ecc2.verify(message, signature, ecc1.getPublicKey());
        
        TestUtils.assert(!isValid, 'Signature should be invalid for wrong public key');
    });
    
    // Test 9: ECC ECDH key exchange
    TestUtils.runTest('ECC', 'ECDH key exchange', () => {
        const alice = new ECC();
        const bob = new ECC();
        
        // Alice computes shared secret using Bob's public key
        const aliceSharedSecret = alice.computeSharedSecret(bob.getPublicKey());
        
        // Bob computes shared secret using Alice's public key
        const bobSharedSecret = bob.computeSharedSecret(alice.getPublicKey());
        
        TestUtils.assertEqual(aliceSharedSecret, bobSharedSecret, 'Shared secrets should match');
    });
    
    // Test 10: ECC bigIntToHex and hexToBigInt utility functions
    TestUtils.runTest('ECC', 'bigIntToHex and hexToBigInt utilities', () => {
        const originalValue = 123456789n;
        const hex = ECC.bigIntToHex(originalValue);
        const bigIntFromHex = ECC.hexToBigInt(hex);
        
        TestUtils.assertEqual(bigIntFromHex, originalValue, 'Hex conversion should be reversible');
    });
    
    // Test 11: ECC bytesToHex and hexToBytes utility functions
    TestUtils.runTest('ECC', 'bytesToHex and hexToBytes utilities', () => {
        const originalBytes = new Uint8Array([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]);
        const hex = ECC.bytesToHex(originalBytes);
        const bytesFromHex = ECC.hexToBytes(hex);
        
        TestUtils.assertArraysEqual(bytesFromHex, originalBytes, 'Hex conversion should be reversible');
    });
    
    // Test 12: ECC with different instances
    TestUtils.runTest('ECC', 'Different instances produce different keys', () => {
        const ecc1 = new ECC();
        const ecc2 = new ECC();
        
        const privateKey1 = ecc1.getPrivateKey();
        const privateKey2 = ecc2.getPrivateKey();
        const publicKey1 = ecc1.getPublicKey();
        const publicKey2 = ecc2.getPublicKey();
        
        // Private keys should be different
        TestUtils.assert(privateKey1 !== privateKey2, 'Different instances should produce different private keys');
        
        // Public keys should be different
        TestUtils.assert(publicKey1.x !== publicKey2.x || publicKey1.y !== publicKey2.y, 'Different instances should produce different public keys');
    });
    
    // Test 13: ECC with special characters in message
    TestUtils.runTest('ECC', 'Special characters in message', () => {
        const ecc = new ECC();
        const message = 'Special chars: !@#$%^&*()_+-=[]{}|;:,.<>?';
        
        const signature = ecc.sign(message);
        const isValid = ecc.verify(message, signature, ecc.getPublicKey());
        
        TestUtils.assert(isValid, 'Signature should be valid for message with special characters');
    });
    
    // Test 14: ECC with Unicode characters in message
    TestUtils.runTest('ECC', 'Unicode characters in message', () => {
        const ecc = new ECC();
        const message = 'Unicode test: 你好, こんにちは, 안녕하세요, Привет, مرحبا';
        
        const signature = ecc.sign(message);
        const isValid = ecc.verify(message, signature, ecc.getPublicKey());
        
        TestUtils.assert(isValid, 'Signature should be valid for Unicode message');
    });
    
    // Test 15: ECC with empty message
    TestUtils.runTest('ECC', 'Empty message', () => {
        const ecc = new ECC();
        const message = '';
        
        const signature = ecc.sign(message);
        const isValid = ecc.verify(message, signature, ecc.getPublicKey());
        
        TestUtils.assert(isValid, 'Signature should be valid for empty message');
    });
    
    // Test 16: ECC signature consistency
    TestUtils.runTest('ECC', 'Signature consistency', () => {
        const ecc = new ECC();
        const message = 'This is a message to be signed using ECDSA.';
        
        const signature1 = ecc.sign(message);
        const signature2 = ecc.sign(message);
        
        // Signatures should be different due to random k
        TestUtils.assert(signature1.r !== signature2.r || signature1.s !== signature2.s, 'Same message should produce different signatures');
        
        // But both should verify
        const isValid1 = ecc.verify(message, signature1, ecc.getPublicKey());
        const isValid2 = ecc.verify(message, signature2, ecc.getPublicKey());
        
        TestUtils.assert(isValid1, 'First signature should be valid');
        TestUtils.assert(isValid2, 'Second signature should be valid');
    });
    
    // Test 17: ECC with invalid signature values
    TestUtils.runTest('ECC', 'Invalid signature values', () => {
        const ecc = new ECC();
        const message = 'This is a message to be signed using ECDSA.';
        
        // Create invalid signature with r = 0
        const invalidSignature1 = { r: 0n, s: 12345n };
        const isValid1 = ecc.verify(message, invalidSignature1, ecc.getPublicKey());
        
        TestUtils.assert(!isValid1, 'Signature with r = 0 should be invalid');
        
        // Create invalid signature with s = 0
        const invalidSignature2 = { r: 12345n, s: 0n };
        const isValid2 = ecc.verify(message, invalidSignature2, ecc.getPublicKey());
        
        TestUtils.assert(!isValid2, 'Signature with s = 0 should be invalid');
    });
    
    // Test 18: ECC with signature values at bounds
    TestUtils.runTest('ECC', 'Signature values at bounds', () => {
        const ecc = new ECC();
        const message = 'This is a message to be signed using ECDSA.';
        
        const signature = ecc.sign(message);
        const n = ECC.hexToBigInt('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
        
        // Signature values should be in range [1, n-1]
        TestUtils.assert(signature.r >= 1n && signature.r < n, 'Signature r should be in valid range');
        TestUtils.assert(signature.s >= 1n && signature.s < n, 'Signature s should be in valid range');
    });
    
    // Test 19: ECC with private key at bounds
    TestUtils.runTest('ECC', 'Private key at bounds', () => {
        const n = ECC.hexToBigInt('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
        
        // Test with private key = 1
        const ecc1 = new ECC(1n);
        const privateKey1 = ecc1.getPrivateKey();
        TestUtils.assertEqual(privateKey1, 1n, 'Private key should be 1');
        
        // Test with private key = n-1
        const ecc2 = new ECC(n - 1n);
        const privateKey2 = ecc2.getPrivateKey();
        TestUtils.assertEqual(privateKey2, n - 1n, 'Private key should be n-1');
    });
    
    // Test 20: ECC key import/export round trip
    TestUtils.runTest('ECC', 'Key import/export round trip', () => {
        const ecc1 = new ECC();
        const privateKey = ecc1.getPrivateKey();
        const publicKey = ecc1.getPublicKey();
        
        // Create new instance with the same private key
        const ecc2 = new ECC(privateKey);
        const privateKey2 = ecc2.getPrivateKey();
        const publicKey2 = ecc2.getPublicKey();
        
        TestUtils.assertEqual(privateKey, privateKey2, 'Private key should match after import/export');
        TestUtils.assertEqual(publicKey.x, publicKey2.x, 'Public key x should match after import/export');
        TestUtils.assertEqual(publicKey.y, publicKey2.y, 'Public key y should match after import/export');
        
        // Test ECDH with imported key
        const aliceSharedSecret = ecc1.computeSharedSecret(publicKey2);
        const bobSharedSecret = ecc2.computeSharedSecret(publicKey);
        
        TestUtils.assertEqual(aliceSharedSecret, bobSharedSecret, 'ECDH should work with imported key');
    });
    
    console.log('ECC Tests completed.');
}

module.exports = { runECCTests };