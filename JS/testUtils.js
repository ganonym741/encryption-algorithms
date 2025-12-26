class TestUtils {
    /**
     * Run a test and record result
     */
    static runTest(algorithm, testName, testFn) {
        const startTime = performance.now();
        let passed = false;
        let error = undefined;

        try {
            const result = testFn();
            if (result instanceof Promise) {
                // Handle async tests
                result.then(() => {
                    passed = true;
                    this.recordResult(algorithm, testName, passed, undefined, performance.now() - startTime);
                }).catch((err) => {
                    error = err.message || String(err);
                    this.recordResult(algorithm, testName, passed, error, performance.now() - startTime);
                });
            } else {
                passed = true;
                this.recordResult(algorithm, testName, passed, undefined, performance.now() - startTime);
            }
        } catch (err) {
            error = (err).message || String(err);
            this.recordResult(algorithm, testName, passed, error, performance.now() - startTime);
        }
    }

    /**
     * Record a test result
     */
    static recordResult(algorithm, testName, passed, error, duration) {
        this.results.push({
            algorithm,
            testName,
            passed,
            error,
            duration: duration || 0
        });
    }

    /**
     * Assert that a condition is true
     */
    static assert(condition, message) {
        if (!condition) {
            throw new Error(message || 'Assertion failed');
        }
    }

    /**
     * Assert that two values are equal
     */
    static assertEqual(actual, expected, message) {
        if (actual !== expected) {
            throw new Error(message || `Expected ${expected}, but got ${actual}`);
        }
    }

    /**
     * Assert that two arrays are equal
     */
    static assertArraysEqual(actual, expected, message) {
        if (actual.length !== expected.length) {
            throw new Error(message || `Arrays have different lengths: expected ${expected.length}, got ${actual.length}`);
        }
        
        for (let i = 0; i < actual.length; i++) {
            if (actual[i] !== expected[i]) {
                throw new Error(message || `Arrays differ at index ${i}: expected ${expected[i]}, got ${actual[i]}`);
            }
        }
    }

    /**
     * Assert that a function throws an error
     */
    static assertThrows(fn, expectedErrorMessage) {
        try {
            fn();
            throw new Error('Expected function to throw an error, but it did not');
        } catch (err) {
            if (expectedErrorMessage && !(err).message.includes(expectedErrorMessage)) {
                throw new Error(`Expected error message to contain "${expectedErrorMessage}", but got "${(err).message}"`);
            }
        }
    }

    /**
     * Generate random test data
     */
    static generateRandomBytes(length) {
        const bytes = new Uint8Array(length);
        for (let i = 0; i < length; i++) {
            bytes[i] = Math.floor(Math.random() * 256);
        }
        return bytes;
    }

    /**
     * Generate a random string
     */
    static generateRandomString(length) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let result = '';
        for (let i = 0; i < length; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
    }

    /**
     * Convert Uint8Array to hex string for comparison
     */
    static bytesToHex(bytes) {
        return Array.from(bytes)
            .map(byte => byte.toString(16).padStart(2, '0'))
            .join('');
    }

    /**
     * Convert hex string to Uint8Array
     */
    static hexToBytes(hex) {
        if (hex.length % 2 !== 0) {
            throw new Error('Hex string must have even length');
        }
        
        const bytes = new Uint8Array(hex.length / 2);
        
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        
        return bytes;
    }

    /**
     * Get all test results
     */
    static getResults() {
        return [...this.results];
    }

    /**
     * Reset all test results
     */
    static resetResults() {
        this.results = [];
    }

    /**
     * Print a summary of all test results
     */
    static printSummary() {
        const totalTests = this.results.length;
        const passedTests = this.results.filter(r => r.passed).length;
        const failedTests = totalTests - passedTests;
        const totalDuration = this.results.reduce((sum, r) => sum + r.duration, 0);

        console.log('\n===== Test Summary =====');
        console.log(`Total Tests: ${totalTests}`);
        console.log(`Passed: ${passedTests}`);
        console.log(`Failed: ${failedTests}`);
        console.log(`Success Rate: ${((passedTests / totalTests) * 100).toFixed(2)}%`);
        console.log(`Total Duration: ${totalDuration.toFixed(2)}ms`);

        if (failedTests > 0) {
            console.log('\n===== Failed Tests =====');
            this.results
                .filter(r => !r.passed)
                .forEach(r => {
                    console.log(`[${r.algorithm}] ${r.testName}: ${r.error}`);
                });
        }

        console.log('\n===== Test Results by Algorithm =====');
        const resultsByAlgorithm = this.results.reduce((acc, result) => {
            if (!acc[result.algorithm]) {
                acc[result.algorithm] = { passed: 0, failed: 0, duration: 0 };
            }
            if (result.passed) {
                acc[result.algorithm].passed++;
            } else {
                acc[result.algorithm].failed++;
            }
            acc[result.algorithm].duration += result.duration;
            return acc;
        }, {});
        
        Object.entries(resultsByAlgorithm).forEach(([algorithm, stats]) => {
            const total = stats.passed + stats.failed;
            const successRate = ((stats.passed / total) * 100).toFixed(2);
            console.log(`${algorithm}: ${stats.passed}/${total} (${successRate}%) - ${stats.duration.toFixed(2)}ms`);
        });
    }
}

TestUtils.results = [];

module.exports = { TestUtils };