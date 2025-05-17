/**
 * Real-World Example: Digital Identity Credential Management
 * 
 * This example demonstrates how to use the SQL module to enhance
 * Schumm's credential revocation architecture in a realistic scenario.
 */

const path = require('path');
const { integrateWithCredentialRevocation } = require('../integration');

// Simulated original credential system
// In a real implementation, this would be imported from Schumm's library
const originalCredentialSystem = {
  async verifyCredential(credentialId, issuanceEpoch) {
    // Simulate Bloom filter check using sub-accumulator
    console.log(`[Original System] Checking credential ${credentialId} from epoch ${issuanceEpoch} against Bloom filter`);
    
    // For demo purposes, we'll say even-numbered credentials are potentially revoked (some are false positives)
    const credNum = parseInt(credentialId.replace(/\D/g, ''));
    const isPotentiallyRevoked = credNum % 2 === 0;
    
    // But only credentials divisible by 4 are actually revoked
    const isActuallyRevoked = credNum % 4 === 0;
    
    return {
      valid: !isPotentiallyRevoked,
      bloomFilterUsed: true,
      epochId: issuanceEpoch
    };
  },
  
  async revokeCredential(credentialId, issuerId, epochId = 1) {
    console.log(`[Original System] Revoking credential ${credentialId} from issuer ${issuerId} in epoch ${epochId}`);
    
    // Map to prime in real system
    const primeValue = BigInt(credentialId.replace(/\D/g, '') || '1').toString();
    
    // Simulate adding to Bloom filter
    return {
      success: true,
      message: 'Credential revoked successfully',
      epochId: epochId,
      primeValue: primeValue
    };
  }
};

// Example usage of the enhanced system
async function runExample() {
  console.log('========================================================');
  console.log('   REAL-WORLD EXAMPLE: DIGITAL IDENTITY CREDENTIALS     ');
  console.log('========================================================');
  console.log('\nInitializing enhanced credential system...');
  
  // Integrate our SQL module with the original system
  const dataDir = path.join(__dirname, '../data');
  const enhancedSystem = integrateWithCredentialRevocation(originalCredentialSystem, { dataDir });
  
  console.log('Enhanced credential system initialized successfully!');
  
  // Scenario 1: Verify a batch of credentials efficiently
  console.log('\n\n=== SCENARIO 1: VERIFYING MULTIPLE CREDENTIALS ===');
  console.log('A university is verifying 5 digital credentials presented by a student');
  
  const studentCredentials = [
    { id: 'degree-credential-123', epoch: 1, description: 'Bachelor Degree Credential' },
    { id: 'course-credential-246', epoch: 1, description: 'Course Completion Credential' },
    { id: 'certificate-credential-357', epoch: 2, description: 'Professional Certificate' },
    { id: 'achievement-credential-468', epoch: 2, description: 'Academic Achievement' },
    { id: 'membership-credential-579', epoch: 1, description: 'Academic Society Membership' }
  ];
  
  console.log('Credentials to verify:');
  studentCredentials.forEach(cred => {
    console.log(`- ${cred.description} (ID: ${cred.id}, Epoch: ${cred.epoch})`);
  });
  
  console.log('\nVerifying credentials using batch verification...');
  console.time('Batch verification');
  const verificationResults = await enhancedSystem.batchVerifyCredentials(studentCredentials);
  console.timeEnd('Batch verification');
  
  console.log('\nVerification Results:');
  studentCredentials.forEach(cred => {
    const result = verificationResults[cred.id];
    console.log(`- ${cred.description}: ${result.valid ? 'VALID' : 'REVOKED'} (Method: ${result.method})`);
  });
  
  // Scenario 2: Revoking credentials efficiently
  console.log('\n\n=== SCENARIO 2: BATCH REVOKING COMPROMISED CREDENTIALS ===');
  console.log('An issuer needs to revoke multiple compromised credentials at once');
  
  const compromisedCredentials = [
    { credential_id: 'compromised-cred-111', epoch_id: 3, issuer_id: 'issuer-x', description: 'Compromised by data breach' },
    { credential_id: 'compromised-cred-222', epoch_id: 3, issuer_id: 'issuer-x', description: 'User reported stolen' },
    { credential_id: 'compromised-cred-333', epoch_id: 3, issuer_id: 'issuer-x', description: 'Suspicious activity detected' }
  ];
  
  console.log('Credentials to revoke:');
  compromisedCredentials.forEach(cred => {
    console.log(`- ${cred.credential_id} (${cred.description})`);
  });
  
  console.log('\nCreating revocation batch...');
  const batchInfo = enhancedSystem.createRevocationBatch();
  console.log(`Batch created with ID: ${batchInfo.batchId}`);
  
  console.log('Adding credentials to batch...');
  enhancedSystem.addToBatch(batchInfo.batchId, compromisedCredentials.map(cred => ({
    ...cred,
    prime_value: BigInt(cred.credential_id.replace(/\D/g, '') || '1').toString()
  })));
  
  console.log('Processing revocation batch...');
  console.time('Batch revocation');
  const revocationResult = await enhancedSystem.processBatch(batchInfo.batchId);
  console.timeEnd('Batch revocation');
  
  console.log(`Batch processing completed: ${revocationResult.success ? 'SUCCESS' : 'FAILED'}`);
  console.log(`Processed ${revocationResult.itemCount} credentials in ${revocationResult.executionTime.toFixed(2)}ms`);
  
  // Scenario 3: Analyzing false positives
  console.log('\n\n=== SCENARIO 3: ANALYZING BLOOM FILTER FALSE POSITIVES ===');
  console.log('System administrator is analyzing false positive rates to tune the Bloom filter parameters');
  
  const fpStats = enhancedSystem.getFalsePositiveStats();
  console.log('False Positive Statistics:');
  fpStats.forEach(epochStats => {
    console.log(`\nEpoch ${epochStats.epoch_id}:`);
    console.log(`- Total false positives detected: ${epochStats.total_false_positives}`);
    console.log(`- Average occurrences per credential: ${epochStats.avg_occurrences.toFixed(2)}`);
    console.log(`- Maximum occurrences for a single credential: ${epochStats.max_occurrences}`);
    
    // Calculate false positive rate (in a real system, this would use actual Bloom filter parameters)
    const estimatedTotal = epochStats.epoch_id * 1000; // Estimate for demo purposes
    const falsePositiveRate = (epochStats.total_false_positives / estimatedTotal) * 100;
    console.log(`- Estimated false positive rate: ${falsePositiveRate.toFixed(2)}%`);
    
    if (falsePositiveRate > 1.0) {
      console.log('  [RECOMMENDATION] Consider adjusting Bloom filter parameters for this epoch');
    }
  });
  
  // Scenario 4: Overall system statistics
  console.log('\n\n=== SCENARIO 4: SYSTEM PERFORMANCE ANALYTICS ===');
  console.log('Monitoring overall system performance and optimization effectiveness');
  
  const revStats = enhancedSystem.getRevocationStats();
  
  console.log('\nRevocation Statistics:');
  console.log(`- Total credentials revoked: ${revStats.totalRevocations}`);
  console.log('\nRevocations by Epoch:');
  revStats.revocationsByEpoch.forEach(epoch => {
    console.log(`- Epoch ${epoch.epoch_id}: ${epoch.count} revocations`);
  });
  
  console.log('\nBatch Processing Statistics:');
  console.log(`- Total batches processed: ${revStats.batchStats.processed_batches}`);
  console.log(`- Average batch size: ${revStats.batchStats.avg_batch_size.toFixed(2)} credentials`);
  console.log(`- Total credentials processed in batches: ${revStats.batchStats.total_items}`);
  
  console.log('\nPerformance Metrics:');
  revStats.performanceMetrics.forEach(metric => {
    console.log(`\n${metric.operation_type.toUpperCase()}:`);
    console.log(`- Operation count: ${metric.operation_count}`);
    console.log(`- Average execution time: ${metric.avg_execution_time.toFixed(2)}ms`);
    console.log(`- Min/Max execution time: ${metric.min_execution_time.toFixed(2)}ms / ${metric.max_execution_time.toFixed(2)}ms`);
  });
  
  console.log('\n========================================================');
  console.log('                 EXAMPLE COMPLETED                      ');
  console.log('========================================================');
}

// Run the example
runExample()
  .catch(error => {
    console.error('Example failed with error:', error);
  });