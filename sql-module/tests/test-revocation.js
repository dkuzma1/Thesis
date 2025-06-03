const path = require('path');
const { initDatabase, closeDatabase } = require('../database');
const RevocationService = require('../services/revocationService');

async function testRevocationService() {
  try {
    console.log('Testing revocation service...');
    
    // Initialize database in a test directory
    const testDataDir = path.join(__dirname, 'test-data');
    initDatabase(testDataDir);
    
    // Create revocation service
    const revocationService = new RevocationService();
    
    // Test 1: Record a single revocation
    console.log('\n1. Testing single revocation:');
    const singleRevocation = {
      credential_id: 'cred-single-123',
      epoch_id: 1,
      issuer_id: 'issuer-1',
      prime_value: '12345678901234567890'
    };
    
    const singleResult = revocationService.recordRevocation(singleRevocation);
    console.log('Single revocation result:', singleResult);
    
    // Test 2: Create a batch and add items
    console.log('\n2. Testing batch creation:');
    const batchId = revocationService.createBatch();
    console.log('Created batch with ID:', batchId);
    
    // Add items to the batch
    const batchItems = [
      {
        credential_id: 'cred-batch-1',
        epoch_id: 1,
        issuer_id: 'issuer-1',
        prime_value: '11111111111111111111'
      },
      {
        credential_id: 'cred-batch-2',
        epoch_id: 2,
        issuer_id: 'issuer-2',
        prime_value: '22222222222222222222'
      },
      {
        credential_id: 'cred-batch-3',
        epoch_id: 1,
        issuer_id: 'issuer-1',
        prime_value: '33333333333333333333'
      }
    ];
    
    const addResult = revocationService.addToBatch(batchId, batchItems);
    console.log('Add to batch result:', addResult);
    
    // Test 3: Process the batch
    console.log('\n3. Testing batch processing:');
    const processResult = revocationService.processBatch(batchId);
    console.log('Batch processing result:', processResult);
    
    // Test 4: Get revocation statistics
    console.log('\n4. Getting revocation statistics:');
    const stats = revocationService.getRevocationStats();
    console.log('Revocation stats:', stats);
    
    // Close database
    closeDatabase();
    
    console.log('\nRevocation service test completed successfully!');
  } catch (error) {
    console.error('Revocation service test failed:', error);
    console.error(error.stack);
  }
}

// Run the test
testRevocationService();