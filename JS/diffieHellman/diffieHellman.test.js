/**
 * Unit tests for Diffie-Hellman key exchange algorithm
 */

const { DiffieHellman } = require('./diffieHellman');
const { TestUtils } = require('../testUtils');

function runDiffieHellmanTests() {
    console.log('Running Diffie-Hellman Tests...');
    
    // Test 1: Basic Diffie-Hellman key exchange
    TestUtils.runTest('Diffie-Hellman', 'Basic key exchange', () => {
        const alice = new DiffieHellman('SMALL_TEST');
        const bobParams = alice.getParameters();
        const bob = new DiffieHellman(bobParams.p, bobParams.g);
        
        // Exchange public keys
        const alicePublicKey = alice.getPublicKey();
        const bobPublicKey = bob.getPublicKey();
        
        // Compute shared secrets
        const aliceSecret = alice.computeSharedSecret(bobPublicKey);
        const bobSecret = bob.computeSharedSecret(alicePublicKey);
        
        TestUtils.assertEqual(aliceSecret, bobSecret, 'Shared secrets should match');
    });
    
    // Test 2: Diffie-Hellman with predefined MODP groups
    TestUtils.runTest('Diffie-Hellman', 'Predefined MODP groups', () => {
        const alice1024 = new DiffieHellman('MODP_1024');
        const bob1024 = new DiffieHellman('MODP_1024');
        
        const aliceSecret1024 = alice1024.computeSharedSecret(bob1024.getPublicKey());
        const bobSecret1024 = bob1024.computeSharedSecret(alice1024.getPublicKey());
        
        TestUtils.assertEqual(aliceSecret1024, bobSecret1024, '1024-bit MODP shared secrets should match');
        
        const alice2048 = new DiffieHellman('MODP_2048');
        const bob2048 = new DiffieHellman('MODP_2048');
        
        const aliceSecret2048 = alice2048.computeSharedSecret(bob2048.getPublicKey());
        const bobSecret2048 = bob2048.computeSharedSecret(alice2048.getPublicKey());
        
        TestUtils.assertEqual(aliceSecret2048, bobSecret2048, '2048-bit MODP shared secrets should match');
    });
    
    // Test 3: Diffie-Hellman with custom parameters
    TestUtils.runTest('Diffie-Hellman', 'Custom parameters', () => {
        const p = 23n; // Small prime for testing
        const g = 5n;  // Generator
        
        const alice = new DiffieHellman(p, g);
        const bob = new DiffieHellman(p, g);
        
        const aliceSecret = alice.computeSharedSecret(bob.getPublicKey());
        const bobSecret = bob.computeSharedSecret(alice.getPublicKey());
        
        TestUtils.assertEqual(aliceSecret, bobSecret, 'Custom parameter shared secrets should match');
    });
    
    // Test 4: Diffie-Hellman get parameters
    TestUtils.runTest('Diffie-Hellman', 'Get parameters', () => {
        const dh = new DiffieHellman('SMALL_TEST');
        const params = dh.getParameters();
        
        TestUtils.assert(!!params.p && !!params.g, 'Parameters should include p and g');
        TestUtils.assertEqual(params.p, 23n, 'Small test group should have p=23');
        TestUtils.assertEqual(params.g, 5n, 'Small test group should have g=5');
    });
    
    // Test 5: Diffie-Hellman get public key
    TestUtils.runTest('Diffie-Hellman', 'Get public key', () => {
        const dh = new DiffieHellman('SMALL_TEST');
        const publicKey = dh.getPublicKey();
        
        TestUtils.assert(publicKey > 1n, 'Public key should be greater than 1');
        TestUtils.assert(publicKey < 23n - 1n, 'Public key should be less than p-1');
    });
    
    // Test 6: Diffie-Hellman with invalid public key
    TestUtils.runTest('Diffie-Hellman', 'Invalid public key', () => {
        const alice = new DiffieHellman('SMALL_TEST');
        
        // Test with public key = 1
        TestUtils.assertThrows(() => {
            alice.computeSharedSecret(1n);
        }, 'Invalid public key');
        
        // Test with public key = p-1
        TestUtils.assertThrows(() => {
            alice.computeSharedSecret(22n); // p-1 for small test group
        }, 'Invalid public key');
    });
    
    // Test 7: Diffie-Hellman performKeyExchange static method
    TestUtils.runTest('Diffie-Hellman', 'performKeyExchange static method', () => {
        const keyExchange = DiffieHellman.performKeyExchange();
        
        TestUtils.assert(!!keyExchange.alice && !!keyExchange.bob, 'Should return Alice and Bob instances');
        TestUtils.assert(keyExchange.secretsMatch, 'Shared secrets should match');
        
        TestUtils.assertEqual(keyExchange.aliceSecret, keyExchange.bobSecret, 'Alice and Bob secrets should be equal');
    });
    
    // Test 8: Diffie-Hellman demonstrateMITMAttack static method
    TestUtils.runTest('Diffie-Hellman', 'demonstrateMITMAttack static method', () => {
        const mitmAttack = DiffieHellman.demonstrateMITMAttack();
        
        TestUtils.assert(mitmAttack.aliceSecret !== mitmAttack.bobSecret, 'Alice and Bob should have different secrets in MITM attack');
        TestUtils.assertEqual(mitmAttack.aliceSecret, mitmAttack.mitmSecretForAlice, 'Mallory should know Alice\'s secret');
        TestUtils.assertEqual(mitmAttack.bobSecret, mitmAttack.mitmSecretForBob, 'Mallory should know Bob\'s secret');
    });
    
    // Test 9: Diffie-Hellman bigIntToHex and hexToBigInt utility functions
    TestUtils.runTest('Diffie-Hellman', 'bigIntToHex and hexToBigInt utilities', () => {
        const originalValue = 123456789n;
        const hex = DiffieHellman.bigIntToHex(originalValue);
        const bigIntFromHex = DiffieHellman.hexToBigInt(hex);
        
        TestUtils.assertEqual(bigIntFromHex, originalValue, 'Hex conversion should be reversible');
    });
    
    // Test 10: Diffie-Hellman bigIntToBytes and bytesToBigInt utility functions
    TestUtils.runTest('Diffie-Hellman', 'bigIntToBytes and bytesToBigInt utilities', () => {
        const originalValue = 123456789n;
        const bytes = DiffieHellman.bigIntToBytes(originalValue);
        const bigIntFromBytes = DiffieHellman.bytesToBigInt(bytes);
        
        TestUtils.assertEqual(bigIntFromBytes, originalValue, 'Byte conversion should be reversible');
    });
    
    // Test 11: Diffie-Hellman with different instances
    TestUtils.runTest('Diffie-Hellman', 'Different instances produce different keys', () => {
        const alice1 = new DiffieHellman('SMALL_TEST');
        const alice2 = new DiffieHellman('SMALL_TEST');
        
        const publicKey1 = alice1.getPublicKey();
        const publicKey2 = alice2.getPublicKey();
        
        // Public keys should be different due to random private keys
        TestUtils.assert(publicKey1 !== publicKey2, 'Different instances should produce different public keys');
    });
    
    // Test 12: Diffie-Hellman shared secret as encryption key
    TestUtils.runTest('Diffie-Hellman', 'Shared secret as encryption key', () => {
        const alice = new DiffieHellman('MODP_1024');
        const bob = new DiffieHellman('MODP_1024');
        
        const aliceSecret = alice.computeSharedSecret(bob.getPublicKey());
        const bobSecret = bob.computeSharedSecret(alice.getPublicKey());
        
        TestUtils.assertEqual(aliceSecret, bobSecret, 'Shared secrets should match');
        
        // Convert shared secret to bytes for use as encryption key
        const sharedSecretBytes = DiffieHellman.bigIntToBytes(aliceSecret);
        TestUtils.assert(sharedSecretBytes.length > 0, 'Shared secret should convert to bytes');
    });
    
    // Test 13: Diffie-Hellman with large group
    TestUtils.runTest('Diffie-Hellman', 'Large group (2048-bit)', () => {
        const alice = new DiffieHellman('MODP_2048');
        const bob = new DiffieHellman('MODP_2048');
        
        const aliceSecret = alice.computeSharedSecret(bob.getPublicKey());
        const bobSecret = bob.computeSharedSecret(alice.getPublicKey());
        
        TestUtils.assertEqual(aliceSecret, bobSecret, '2048-bit shared secrets should match');
        
        // Verify that the shared secret is large
        const secretBytes = DiffieHellman.bigIntToBytes(aliceSecret);
        TestUtils.assert(secretBytes.length >= 256, '2048-bit shared secret should be at least 256 bytes');
    });
    
    // Test 14: Diffie-Hellman key exchange consistency
    TestUtils.runTest('Diffie-Hellman', 'Key exchange consistency', () => {
        const alice = new DiffieHellman('SMALL_TEST');
        const bob = new DiffieHellman('SMALL_TEST');
        
        // Alice computes shared secret
        const aliceSecret1 = alice.computeSharedSecret(bob.getPublicKey());
        const aliceSecret2 = alice.computeSharedSecret(bob.getPublicKey());
        
        // Bob computes shared secret
        const bobSecret1 = bob.computeSharedSecret(alice.getPublicKey());
        const bobSecret2 = bob.computeSharedSecret(alice.getPublicKey());
        
        TestUtils.assertEqual(aliceSecret1, aliceSecret2, 'Alice should compute the same secret consistently');
        TestUtils.assertEqual(bobSecret1, bobSecret2, 'Bob should compute the same secret consistently');
        TestUtils.assertEqual(aliceSecret1, bobSecret1, 'Alice and Bob should compute the same secret');
    });
    
    // Test 15: Diffie-Hellman with zero-based indices
    TestUtils.runTest('Diffie-Hellman', 'Zero-based indices', () => {
        const dh = new DiffieHellman('SMALL_TEST');
        
        // Verify that public key is in valid range
        const publicKey = dh.getPublicKey();
        const params = dh.getParameters();
        
        TestUtils.assert(publicKey > 1n, 'Public key should be greater than 1');
        TestUtils.assert(publicKey < params.p - 1n, 'Public key should be less than p-1');
    });
    
    // Test 16: Diffie-Hellman with same public key
    TestUtils.runTest('Diffie-Hellman', 'Same public key', () => {
        const alice = new DiffieHellman('SMALL_TEST');
        const bob = new DiffieHellman('SMALL_TEST');
        
        // Alice computes shared secret with her own public key
        const aliceSecret = alice.computeSharedSecret(alice.getPublicKey());
        
        // Bob computes shared secret with Alice's public key
        const bobSecret = bob.computeSharedSecret(alice.getPublicKey());
        
        // These should be different
        TestUtils.assert(aliceSecret !== bobSecret, 'Computing shared secret with own key should differ from others');
    });
    
    // Test 17: Diffie-Hellman with very small prime
    TestUtils.runTest('Diffie-Hellman', 'Very small prime', () => {
        const p = 5n; // Very small prime
        const g = 2n; // Generator
        
        const alice = new DiffieHellman(p, g);
        const bob = new DiffieHellman(p, g);
        
        const aliceSecret = alice.computeSharedSecret(bob.getPublicKey());
        const bobSecret = bob.computeSharedSecret(alice.getPublicKey());
        
        TestUtils.assertEqual(aliceSecret, bobSecret, 'Even with very small prime, shared secrets should match');
    });
    
    // Test 18: Diffie-Hellman with generator 1
    TestUtils.runTest('Diffie-Hellman', 'Generator 1', () => {
        const p = 23n; // Small prime for testing
        const g = 1n;  // Generator 1 (trivial case)
        
        const alice = new DiffieHellman(p, g);
        const bob = new DiffieHellman(p, g);
        
        const aliceSecret = alice.computeSharedSecret(bob.getPublicKey());
        const bobSecret = bob.computeSharedSecret(alice.getPublicKey());
        
        // With generator 1, the shared secret should always be 1
        TestUtils.assertEqual(aliceSecret, 1n, 'With generator 1, shared secret should be 1');
        TestUtils.assertEqual(bobSecret, 1n, 'With generator 1, shared secret should be 1');
    });
    
    // Test 19: Diffie-Hellman with prime modulus
    TestUtils.runTest('Diffie-Hellman', 'Prime modulus', () => {
        const p = 23n; // Small prime for testing
        const g = 5n;  // Generator
        
        const alice = new DiffieHellman(p, g);
        const params = alice.getParameters();
        
        TestUtils.assertEqual(params.p, p, 'Modulus should match input');
        TestUtils.assertEqual(params.g, g, 'Generator should match input');
    });
    
    // Test 20: Diffie-Hellman key exchange with multiple parties
    TestUtils.runTest('Diffie-Hellman', 'Multiple party key exchange', () => {
        const alice = new DiffieHellman('SMALL_TEST');
        const bob = new DiffieHellman('SMALL_TEST');
        const carol = new DiffieHellman('SMALL_TEST');
        
        // Alice-Bob shared secret
        const aliceBobSecret = alice.computeSharedSecret(bob.getPublicKey());
        
        // Alice-Carol shared secret
        const aliceCarolSecret = alice.computeSharedSecret(carol.getPublicKey());
        
        // Bob-Carol shared secret
        const bobCarolSecret = bob.computeSharedSecret(carol.getPublicKey());
        
        // All shared secrets should be different
        TestUtils.assert(aliceBobSecret !== aliceCarolSecret, 'Alice-Bob and Alice-Carol secrets should differ');
        TestUtils.assert(aliceBobSecret !== bobCarolSecret, 'Alice-Bob and Bob-Carol secrets should differ');
        TestUtils.assert(aliceCarolSecret !== bobCarolSecret, 'Alice-Carol and Bob-Carol secrets should differ');
    });
    
    console.log('Diffie-Hellman Tests completed.');
}

module.exports = { runDiffieHellmanTests };