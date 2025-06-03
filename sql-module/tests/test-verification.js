const path = require('path');
const { initDatabase, closeDatabase } = require('../database');
const VerificationService = require('../services/verificationService');

async function testVerificationService() {
  try {
    console.log('Testing verification service...');
    
    // Initialize database in a test directory
    const testDataDir = path.join(__dirname, 'test-data');
    initDatabase(testDataDir);
    
    // Create verification service
    const verificationService = new VerificationService();
    
    // Test 1: Bloom filter says not revoked
    console.log('\n1. Testing with bloom filter saying NOT revoked:');
    const result1 = verificationService.verifyCredential('credential-123', 1, false);
    console.log('Result:', result1);
    
    // Test 2: Simulate a false positive by adding to our database
    console.log('\n2. Testing with a false positive:');
    // Bloom filter says it's revoked (true), but it's not actually revoked
    const result2 = verificationService.verifyCredential('credential-456', 1, true);
    console.log('Result:', result2);
    
    // Test 3: Test batch verification
    console.log('\n3. Testing batch verification:');
    const batchResult = verificationService.batchVerifyCredentials([
      { id: 'credential-123', epoch: 1, bloomResult: false },
      { id: 'credential-456', epoch: 1, bloomResult: true },
      { id: 'credential-789', epoch: 2, bloomResult: true }
    ]);
    console.log('Batch results:', batchResult);
    
    // Test 4: Get false positive statistics
    console.log('\n4. Getting false positive statistics:');
    const stats = verificationService.getFalsePositiveStats();
    console.log('False positive stats:', stats);
    
    // Close database
    closeDatabase();
    
    console.log('\nVerification service test completed successfully!');
  } catch (error) {
    console.error('Verification service test failed:', error);
    console.error(error.stack);
  }
}

// Run the test
testVerificationService();