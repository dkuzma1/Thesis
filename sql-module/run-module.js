/**
 * Basic test to initialize and run the SQL module
 */

const path = require('path');
const SQLModule = require('./index');

// Initialize the SQL module
console.log('Initializing SQL Module...');
const dataDir = path.join(__dirname, 'data');
const sqlModule = SQLModule.getInstance({ dataDir });

// Create some test data
const testCredentialId = 'test-credential-123';
const testEpochId = 1;
const testIssuerId = 'test-issuer-1';
const testPrimeValue = '123456789012345678901234567890';

// Test revocation
console.log('\nTesting revocation...');
const revocationResult = sqlModule.recordRevocation({
  credential_id: testCredentialId,
  epoch_id: testEpochId,
  issuer_id: testIssuerId,
  prime_value: testPrimeValue
});

console.log('Revocation result:', revocationResult);

// Test verification (simulating Bloom filter result)
console.log('\nTesting verification with bloom filter true (potentially revoked)...');
const verificationResult1 = sqlModule.verifyCredential(testCredentialId, testEpochId, true);
console.log('Verification result:', verificationResult1);

// Test verification of a credential not in the revoked list
console.log('\nTesting verification of a different credential...');
const verificationResult2 = sqlModule.verifyCredential('other-credential', testEpochId, true);
console.log('Verification result:', verificationResult2);

// Test batch operations
console.log('\nTesting batch operations...');

// Create a batch
const batchId = sqlModule.createRevocationBatch();
console.log('Created batch with ID:', batchId);

// Add items to batch
const batchItems = [
  {
    credential_id: 'batch-cred-1',
    epoch_id: 1,
    issuer_id: 'issuer-1',
    prime_value: '11111'
  },
  {
    credential_id: 'batch-cred-2',
    epoch_id: 1,
    issuer_id: 'issuer-1',
    prime_value: '22222'
  }
];

const addResult = sqlModule.addToBatch(batchId, batchItems);
console.log('Add to batch result:', addResult);

// Process batch
const processResult = sqlModule.processBatch(batchId);
console.log('Process batch result:', processResult);

// Get statistics
console.log('\nGetting statistics...');
const fpStats = sqlModule.getFalsePositiveStats();
console.log('False positive stats:', fpStats);

const revStats = sqlModule.getRevocationStats();
console.log('Revocation stats:', revStats);

console.log('\nSQL Module test completed successfully!');

// Shut down
sqlModule.shutdown();