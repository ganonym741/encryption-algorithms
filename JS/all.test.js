/**
 * Test runner for all encryption algorithms
 */

const { runAESTests } = require('./aes/aes.test.js');
const { runDESTests } = require('./des/des.test.js');
const { runBlowfishTests } = require('./blowfish/blowfish.test.js');
const { runRSATests } = require('./rsa/rsa.test.js');
const { runSHA256Tests } = require('./sha256/sha256.test.js');
const { runDiffieHellmanTests } = require('./diffieHellman/diffieHellman.test.js');
const { runChaCha20Tests } = require('./chacha20/chacha20.test.js');
const { runAESGCMTests } = require('./aesGCM/aesGcm.test.js');
const { runECCTests } = require('./ecc/ecc.test.js');
const { TestUtils } = require('./testUtils.js');

function runAllTests() {
    console.log('===== Running All Encryption Algorithm Tests =====\n');
    
    TestUtils.resetResults();
    
    runAESTests();
    runDESTests();
    runBlowfishTests();
    runRSATests();
    runSHA256Tests();
    runDiffieHellmanTests();
    runChaCha20Tests();
    runAESGCMTests();
    runECCTests();
    
    TestUtils.printSummary();
}

runAllTests();