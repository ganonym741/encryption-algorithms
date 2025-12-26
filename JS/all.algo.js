const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// List of all basic algorithm files
const algoFiles = [
    'aes/aes.js',
    'des/des.js',
    'blowfish/blowfish.js',
    'rsa/rsa.js',
    'sha256/sha256.js',
    'diffieHellman/diffieHellman.js',
    'ecc/ecc.js',
    'chacha20/chacha20.js',
    'aesGCM/aesGcm.js'
];

function runAllAlgos() {
    console.log('===== Running All Basic Algorithm Implementations =====\n');
    
    algoFiles.forEach((file, index) => {
        const filePath = path.join(__dirname, file);
        const fileName = path.basename(file, '.js');
        
        if (fs.existsSync(filePath)) {
            console.log(`\n--- ${fileName.toUpperCase()} Algorithm ---`);
            try {
                const algoModule = require(filePath);
                if (algoModule.example && typeof algoModule.example === 'function') {
                    console.log(`Running ${fileName} example...`);
                    algoModule.example();
                } else {
                    console.log(`No example function found in ${fileName}`);
                }
            } catch (error) {
                console.error(`Error running ${fileName} algorithm:`, error.message);
            }
        } else {
            console.log(`Algorithm file not found: ${file}`);
        }
    });
    
    console.log('\n===== All Algorithm Implementations Completed =====');
}

if (require.main === module) {
    runAllAlgos();
}

module.exports = { runAllAlgos };