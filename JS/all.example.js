const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const exampleFiles = [
    'aes/aes.example.js',
    'des/des.example.js',
    'blowfish/blowfish.example.js',
    'rsa/rsa.example.js',
    'sha256/sha256.example.js',
    'diffieHellman/diffieHellman.example.js',
    'ecc/ecc.example.js',
    'chacha20/chacha20.example.js',
    'aesGCM/aesGcm.example.js'
];

function runAllExamples() {
    console.log('===== Running All Educational Examples =====\n');
    
    exampleFiles.forEach((file, index) => {
        const filePath = path.join(__dirname, file);
        const fileName = path.basename(file, '.example.js');
        
        if (fs.existsSync(filePath)) {
            console.log(`\n--- ${fileName.toUpperCase()} Example ---`);
            try {
                execSync(`node "${filePath}"`, { stdio: 'inherit', cwd: __dirname });
            } catch (error) {
                console.error(`Error running ${fileName} example:`, error.message);
            }
        } else {
            console.log(`Example file not found: ${file}`);
        }
    });
    
    console.log('\n===== All Examples Completed =====');
}

if (require.main === module) {
    runAllExamples();
}

module.exports = { runAllExamples };