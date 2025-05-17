const { integrateWithCredentialRevocation } = require('./integration');

// Mock of Schumm's original credential revocation system
const mockOriginalSystem = {
  async verifyCredential(credentialId, issuanceEpoch) {
    console.log(`Original system verifying credential: ${credentialId} from epoch ${issuanceEpoch}`);
    
    // Simulate Bloom filter check
    // For testing, we'll say credentials with even IDs are revoked
    const isRevoked = credentialId.endsWith('2') || credentialId.endsWith('4');
    
    // But introduce some false positives (credentials that end with 6 will be false positives)
    const isFalsePositive = credentialId.endsWith('6');
    
    return {
      valid: !(isRevoked || isFalsePositive),
      bloomFilterUsed: true
    };
  },
  
  async revokeCredential(credentialId, issuerId) {
    console.log(`Original system revoking credential: ${credentialId} from issuer ${issuerId}`);
    
    // Simulate adding to Bloom filter
    return {
      success: true,
      epochId: 1,
      primeValue: '123456789012345678901234567890'
    };
  }
};

async function testIntegration() {
  try {
    console.log('Testing SQL module integration...');
    
    // Integrate the SQL module with the mock original system
    const enhancedSystem = integrateWithCredentialRevocation(mockOriginalSystem, {
      dataDir: './sql-module/test-data'
    });
    
    // Test verification (expected to be valid)
    console.log('\n1. Testing verification of a valid credential:');
    const verifyResult1 = await enhancedSystem.verifyCredential('credential-1', 1);
    console.log('Verification result:', verifyResult1);
    
    // Test verification (expected to be revoked)
    console.log('\n2. Testing verification of a revoked credential:');
    const verifyResult2 = await enhancedSystem.verifyCredential('credential-2', 1);
    console.log('Verification result:', verifyResult2);
    
    // Test verification (expected to be a false positive)
    console.log('\n3. Testing verification of a credential with false positive:');
    const verifyResult3 = await enhancedSystem.verifyCredential('credential-6', 1);
    console.log('Verification result:', verifyResult3);
    
    // Test revocation
    console.log('\n4. Testing revocation:');
    const revokeResult = await enhancedSystem.revokeCredential('credential-5', 'issuer-1');
    console.log('Revocation result:', revokeResult);
    
    // Test batch verification
    console.log('\n5. Testing batch verification:');
    const batchResult = await enhancedSystem.batchVerifyCredentials([
      { id: 'credential-1', epoch: 1 },
      { id: 'credential-2', epoch: 1 },
      { id: 'credential-6', epoch: 1 }
    ]);
    console.log('Batch verification result:', batchResult);
    
    // Test batch revocation
    console.log('\n6. Testing batch revocation:');
    const batchId = enhancedSystem.createRevocationBatch().batchId;
    console.log('Created batch with ID:', batchId);
    
    const addResult = enhancedSystem.addToBatch(batchId, [
      { credential_id: 'batch-cred-1', epoch_id: 1, issuer_id: 'issuer-1', prime_value: '11111' },
      { credential_id: 'batch-cred-2', epoch_id: 1, issuer_id: 'issuer-1', prime_value: '22222' }
    ]);
    console.log('Add to batch result:', addResult);
    
    const processResult = await enhancedSystem.processBatch(batchId);
    console.log('Process batch result:', processResult);
    
    // Get statistics
    console.log('\n7. Getting statistics:');
    const fpStats = enhancedSystem.getFalsePositiveStats();
    console.log('False positive stats:', fpStats);
    
    const revStats = enhancedSystem.getRevocationStats();
    console.log('Revocation stats:', revStats);
    
    console.log('\nIntegration test completed successfully!');
  } catch (error) {
    console.error('Integration test failed:', error);
    console.error(error.stack);
  }
}

// Run the test
testIntegration();