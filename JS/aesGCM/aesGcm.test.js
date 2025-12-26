/**
 * Unit tests for AES-GCM authenticated encryption algorithm
 */

const { AESGCM } = require('./aesGcm');
const { TestUtils } = require('../testUtils');

function runAESGCMTests() {
    console.log('Running AES-GCM Tests...');
    
    // Test 1: Basic AES-GCM encryption and decryption
    TestUtils.runTest('AES-GCM', 'Basic encryption and decryption', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const iv = '69f71e2ae0c1'; // 12 bytes
        const aesGcm = new AESGCM(key, iv);
        const plaintext = 'This is a test message for AES-GCM encryption.';
        const aad = 'Additional authenticated data';
        
        const { ciphertext, tag } = aesGcm.encrypt(plaintext, aad);
        const decrypted = aesGcm.decrypt(ciphertext, tag, aad);
        const decryptedText = decrypted ? new TextDecoder().decode(decrypted) : 'Decryption failed';
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original');
    });
    
    // Test 2: AES-GCM encryption without AAD
    TestUtils.runTest('AES-GCM', 'Encryption without AAD', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const iv = '69f71e2ae0c1'; // 12 bytes
        const aesGcm = new AESGCM(key, iv);
        const plaintext = 'This is a test message for AES-GCM without AAD.';
        
        const { ciphertext, tag } = aesGcm.encrypt(plaintext);
        const decrypted = aesGcm.decrypt(ciphertext, tag);
        const decryptedText = decrypted ? new TextDecoder().decode(decrypted) : 'Decryption failed';
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original');
    });
    
    // Test 3: AES-GCM encryption with binary data
    TestUtils.runTest('AES-GCM', 'Binary data encryption', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const iv = '69f71e2ae0c1'; // 12 bytes
        const aesGcm = new AESGCM(key, iv);
        const binaryData = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC]);
        const aad = new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD]);
        
        const { ciphertext, tag } = aesGcm.encrypt(binaryData, aad);
        const decrypted = aesGcm.decrypt(ciphertext, tag, aad);
        
        TestUtils.assertArraysEqual(decrypted, binaryData, 'Decrypted binary data should match original');
    });
    
    // Test 4: AES-GCM empty string encryption
    TestUtils.runTest('AES-GCM', 'Empty string encryption', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const iv = '69f71e2ae0c1'; // 12 bytes
        const aesGcm = new AESGCM(key, iv);
        const plaintext = '';
        const aad = 'Additional authenticated data';
        
        const { ciphertext, tag } = aesGcm.encrypt(plaintext, aad);
        const decrypted = aesGcm.decrypt(ciphertext, tag, aad);
        const decryptedText = decrypted ? new TextDecoder().decode(decrypted) : 'Decryption failed';
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted empty string should match original');
    });
    
    // Test 5: AES-GCM large message encryption
    TestUtils.runTest('AES-GCM', 'Large message encryption', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const iv = '69f71e2ae0c1'; // 12 bytes
        const aesGcm = new AESGCM(key, iv);
        const plaintext = 'This is a much longer message that spans multiple AES-GCM blocks. '.repeat(10);
        const aad = 'Additional authenticated data';
        
        const { ciphertext, tag } = aesGcm.encrypt(plaintext, aad);
        const decrypted = aesGcm.decrypt(ciphertext, tag, aad);
        const decryptedText = decrypted ? new TextDecoder().decode(decrypted) : 'Decryption failed';
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted large message should match original');
    });
    
    // Test 6: AES-GCM different keys produce different ciphertexts
    TestUtils.runTest('AES-GCM', 'Different keys produce different ciphertexts', () => {
        const key1 = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const key2 = 'other-secret-key-32-bytes-long-123'; // 32 bytes
        const iv = '69f71e2ae0c1'; // 12 bytes
        const plaintext = 'This is a test message.';
        const aad = 'Additional authenticated data';
        
        const aesGcm1 = new AESGCM(key1, iv);
        const aesGcm2 = new AESGCM(key2, iv);
        
        const { ciphertext: ciphertext1, tag: tag1 } = aesGcm1.encrypt(plaintext, aad);
        const { ciphertext: ciphertext2, tag: tag2 } = aesGcm2.encrypt(plaintext, aad);
        
        // Ciphertexts should be different
        let ciphertextsMatch = true;
        if (ciphertext1.length !== ciphertext2.length) {
            ciphertextsMatch = false;
        } else {
            for (let i = 0; i < ciphertext1.length; i++) {
                if (ciphertext1[i] !== ciphertext2[i]) {
                    ciphertextsMatch = false;
                    break;
                }
            }
        }
        
        // Tags should also be different
        let tagsMatch = true;
        if (tag1.length !== tag2.length) {
            tagsMatch = false;
        } else {
            for (let i = 0; i < tag1.length; i++) {
                if (tag1[i] !== tag2[i]) {
                    tagsMatch = false;
                    break;
                }
            }
        }
        
        TestUtils.assert(!ciphertextsMatch, 'Different keys should produce different ciphertexts');
        TestUtils.assert(!tagsMatch, 'Different keys should produce different tags');
    });
    
    // Test 7: AES-GCM different IVs produce different ciphertexts
    TestUtils.runTest('AES-GCM', 'Different IVs produce different ciphertexts', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const iv1 = '69f71e2ae0c1'; // 12 bytes
        const iv2 = 'other-iv-12'; // 12 bytes
        const plaintext = 'This is a test message.';
        const aad = 'Additional authenticated data';
        
        const aesGcm1 = new AESGCM(key, iv1);
        const aesGcm2 = new AESGCM(key, iv2);
        
        const { ciphertext: ciphertext1, tag: tag1 } = aesGcm1.encrypt(plaintext, aad);
        const { ciphertext: ciphertext2, tag: tag2 } = aesGcm2.encrypt(plaintext, aad);
        
        // Ciphertexts should be different
        let ciphertextsMatch = true;
        if (ciphertext1.length !== ciphertext2.length) {
            ciphertextsMatch = false;
        } else {
            for (let i = 0; i < ciphertext1.length; i++) {
                if (ciphertext1[i] !== ciphertext2[i]) {
                    ciphertextsMatch = false;
                    break;
                }
            }
        }
        
        // Tags should also be different
        let tagsMatch = true;
        if (tag1.length !== tag2.length) {
            tagsMatch = false;
        } else {
            for (let i = 0; i < tag1.length; i++) {
                if (tag1[i] !== tag2[i]) {
                    tagsMatch = false;
                    break;
                }
            }
        }
        
        TestUtils.assert(!ciphertextsMatch, 'Different IVs should produce different ciphertexts');
        TestUtils.assert(!tagsMatch, 'Different IVs should produce different tags');
    });
    
    // Test 8: AES-GCM invalid key size
    TestUtils.runTest('AES-GCM', 'Invalid key size', () => {
        const iv = '69f71e2ae0c1'; // 12 bytes
        
        TestUtils.assertThrows(() => {
            new AESGCM('short-key', iv); // Less than 32 bytes
        }, 'AES-GCM key must be 32 bytes for AES-256');
    });
    
    // Test 9: AES-GCM invalid IV size
    TestUtils.runTest('AES-GCM', 'Invalid IV size', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        
        TestUtils.assertThrows(() => {
            new AESGCM(key, 'short-iv'); // Less than 12 bytes
        }, 'AES-GCM IV must be 12 bytes');
    });
    
    // Test 10: AES-GCM key and IV as Uint8Array
    TestUtils.runTest('AES-GCM', 'Key and IV as Uint8Array', () => {
        const keyBytes = new Uint8Array(32);
        for (let i = 0; i < 32; i++) {
            keyBytes[i] = i;
        }
        
        const ivBytes = new Uint8Array(12);
        for (let i = 0; i < 12; i++) {
            ivBytes[i] = i;
        }
        
        const aesGcm = new AESGCM(keyBytes, ivBytes);
        const plaintext = 'This is a test message.';
        const aad = 'Additional authenticated data';
        
        const { ciphertext, tag } = aesGcm.encrypt(plaintext, aad);
        const decrypted = aesGcm.decrypt(ciphertext, tag, aad);
        const decryptedText = decrypted ? new TextDecoder().decode(decrypted) : 'Decryption failed';
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original');
    });
    
    // Test 11: AES-GCM plaintext as Uint8Array
    TestUtils.runTest('AES-GCM', 'Plaintext as Uint8Array', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const iv = '69f71e2ae0c1'; // 12 bytes
        const aesGcm = new AESGCM(key, iv);
        const plaintextBytes = new TextEncoder().encode('This is a test message.');
        const aad = 'Additional authenticated data';
        
        const { ciphertext, tag } = aesGcm.encrypt(plaintextBytes, aad);
        const decrypted = aesGcm.decrypt(ciphertext, tag, aad);
        
        TestUtils.assertArraysEqual(decrypted, plaintextBytes, 'Decrypted bytes should match original');
    });
    
    // Test 12: AES-GCM toHex and fromHex utility functions
    TestUtils.runTest('AES-GCM', 'toHex and fromHex utilities', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const iv = '69f71e2ae0c1'; // 12 bytes
        const aesGcm = new AESGCM(key, iv);
        const plaintext = 'This is a test message.';
        const aad = 'Additional authenticated data';
        
        const { ciphertext, tag } = aesGcm.encrypt(plaintext, aad);
        const ciphertextHex = AESGCM.toHex(ciphertext);
        const ciphertextFromHex = AESGCM.fromHex(ciphertextHex);
        
        TestUtils.assertArraysEqual(ciphertext, ciphertextFromHex, 'Ciphertext hex conversion should be reversible');
        
        const tagHex = AESGCM.toHex(tag);
        const tagFromHex = AESGCM.fromHex(tagHex);
        
        TestUtils.assertArraysEqual(tag, tagFromHex, 'Tag hex conversion should be reversible');
        
        const decrypted = aesGcm.decrypt(ciphertextFromHex, tagFromHex, aad);
        const decryptedText = decrypted ? new TextDecoder().decode(decrypted) : 'Decryption failed';
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original after hex conversion');
    });
    
    // Test 13: AES-GCM with special characters
    TestUtils.runTest('AES-GCM', 'Special characters encryption', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const iv = '69f71e2ae0c1'; // 12 bytes
        const aesGcm = new AESGCM(key, iv);
        const plaintext = 'Special chars: !@#$%^&*()_+-=[]{}|;:,.<>?';
        const aad = 'Additional authenticated data';
        
        const { ciphertext, tag } = aesGcm.encrypt(plaintext, aad);
        const decrypted = aesGcm.decrypt(ciphertext, tag, aad);
        const decryptedText = decrypted ? new TextDecoder().decode(decrypted) : 'Decryption failed';
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text with special chars should match original');
    });
    
    // Test 14: AES-GCM with Unicode characters
    TestUtils.runTest('AES-GCM', 'Unicode characters encryption', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const iv = '69f71e2ae0c1'; // 12 bytes
        const aesGcm = new AESGCM(key, iv);
        const plaintext = 'Unicode test: 你好, こんにちは, 안녕하세요, Привет, مرحبا';
        const aad = 'Additional authenticated data';
        
        const { ciphertext, tag } = aesGcm.encrypt(plaintext, aad);
        const decrypted = aesGcm.decrypt(ciphertext, tag, aad);
        const decryptedText = decrypted ? new TextDecoder().decode(decrypted) : 'Decryption failed';
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted Unicode text should match original');
    });
    
    // Test 15: AES-GCM with wrong AAD (should fail)
    TestUtils.runTest('AES-GCM', 'Wrong AAD (should fail)', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const iv = '69f71e2ae0c1'; // 12 bytes
        const aesGcm = new AESGCM(key, iv);
        const plaintext = 'This is a test message.';
        const aad = 'Additional authenticated data';
        const wrongAad = 'Wrong additional data';
        
        const { ciphertext, tag } = aesGcm.encrypt(plaintext, aad);
        const decrypted = aesGcm.decrypt(ciphertext, tag, wrongAad);
        
        TestUtils.assert(decrypted === null, 'Decryption with wrong AAD should fail');
    });
    
    // Test 16: AES-GCM with wrong tag (should fail)
    TestUtils.runTest('AES-GCM', 'Wrong tag (should fail)', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const iv = '69f71e2ae0c1'; // 12 bytes
        const aesGcm = new AESGCM(key, iv);
        const plaintext = 'This is a test message.';
        const aad = 'Additional authenticated data';
        
        const { ciphertext, tag } = aesGcm.encrypt(plaintext, aad);
        
        // Modify one bit in tag
        const wrongTag = new Uint8Array(tag);
        if (wrongTag.length > 0) {
            wrongTag[0] ^= 0x01;
        }
        
        const decrypted = aesGcm.decrypt(ciphertext, wrongTag, aad);
        
        TestUtils.assert(decrypted === null, 'Decryption with wrong tag should fail');
    });
    
    // Test 17: AES-GCM with modified ciphertext (should fail)
    TestUtils.runTest('AES-GCM', 'Modified ciphertext (should fail)', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const iv = '69f71e2ae0c1'; // 12 bytes
        const aesGcm = new AESGCM(key, iv);
        const plaintext = 'This is a test message.';
        const aad = 'Additional authenticated data';
        
        const { ciphertext, tag } = aesGcm.encrypt(plaintext, aad);
        
        // Modify one bit in ciphertext
        const modifiedCiphertext = new Uint8Array(ciphertext);
        if (modifiedCiphertext.length > 0) {
            modifiedCiphertext[0] ^= 0x01;
        }
        
        const decrypted = aesGcm.decrypt(modifiedCiphertext, tag, aad);
        
        TestUtils.assert(decrypted === null, 'Decryption with modified ciphertext should fail');
    });
    
    // Test 18: AES-GCM with empty AAD
    TestUtils.runTest('AES-GCM', 'Empty AAD', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const iv = '69f71e2ae0c1'; // 12 bytes
        const aesGcm = new AESGCM(key, iv);
        const plaintext = 'This is a test message.';
        const aad = '';
        
        const { ciphertext, tag } = aesGcm.encrypt(plaintext, aad);
        const decrypted = aesGcm.decrypt(ciphertext, tag, aad);
        const decryptedText = decrypted ? new TextDecoder().decode(decrypted) : 'Decryption failed';
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original');
    });
    
    // Test 19: AES-GCM with large AAD
    TestUtils.runTest('AES-GCM', 'Large AAD', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const iv = '69f71e2ae0c1'; // 12 bytes
        const aesGcm = new AESGCM(key, iv);
        const plaintext = 'This is a test message.';
        const aad = 'Large additional authenticated data. '.repeat(10);
        
        const { ciphertext, tag } = aesGcm.encrypt(plaintext, aad);
        const decrypted = aesGcm.decrypt(ciphertext, tag, aad);
        const decryptedText = decrypted ? new TextDecoder().decode(decrypted) : 'Decryption failed';
        
        TestUtils.assertEqual(decryptedText, plaintext, 'Decrypted text should match original');
    });
    
    // Test 20: AES-GCM same key and IV but different instances
    TestUtils.runTest('AES-GCM', 'Same key and IV produce same ciphertext', () => {
        const key = '63f4945d921d599f27ae4fdf5bada3f1'; // 32 bytes
        const iv = '69f71e2ae0c1'; // 12 bytes
        const plaintext = 'This is a test message.';
        const aad = 'Additional authenticated data';
        
        const aesGcm1 = new AESGCM(key, iv);
        const aesGcm2 = new AESGCM(key, iv);
        
        const { ciphertext: ciphertext1, tag: tag1 } = aesGcm1.encrypt(plaintext, aad);
        const { ciphertext: ciphertext2, tag: tag2 } = aesGcm2.encrypt(plaintext, aad);
        
        TestUtils.assertArraysEqual(ciphertext1, ciphertext2, 'Same key and IV should produce same ciphertext');
        TestUtils.assertArraysEqual(tag1, tag2, 'Same key and IV should produce same tag');
    });
    
    console.log('AES-GCM Tests completed.');
}

module.exports = { runAESGCMTests };