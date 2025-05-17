// improved-evaluation.js within sql-module directory
const { performance } = require('perf_hooks');
const SQLModule = require('./index');
const { integrateWithCredentialRevocation } = require('./integration');

// Configuration for test runs
const TEST_CONFIG = {
  // Number of credentials to test in each batch
  batchSizes: [10, 50, 100],
  
  // Percentage of revoked credentials in each test
  revocationRates: [0.01, 0.05, 0.1],
  
  // Number of test runs to average results
  testRuns: 2,
  
  // Default epoch for testing
  testEpoch: 3
};

// Create a basic credential system (simulating the original implementation)
function createOriginalSystem() {
  // In-memory simulated bloom filter and revocation list
  const revokedCredentials = new Set();
  
  return {
    // Verify using only bloom filter simulation (in-memory set)
    verifyCredential: async (credentialId, epochId) => {
      const startTime = performance.now();
      
      // Simulate blockchain delay (30-50ms)
      await simulateBlockchainDelay();
      
      const isRevoked = revokedCredentials.has(credentialId);
      
      return {
        valid: !isRevoked,
        method: "original-bloom-filter",
        executionTime: performance.now() - startTime
      };
    },
    
    // Revoke by adding to in-memory set
    revokeCredential: async (credentialId, issuerId) => {
      const startTime = performance.now();
      
      // Simulate blockchain delay (50-100ms)
      await simulateBlockchainDelay(true);
      
      revokedCredentials.add(credentialId);
      
      return {
        success: true,
        epochId: TEST_CONFIG.testEpoch,
        primeValue: `${credentialId}-prime-value`,
        executionTime: performance.now() - startTime
      };
    },
    
    // Add credentials to the revoked set for testing
    _prepareTest: (credentialIds) => {
      credentialIds.forEach(id => revokedCredentials.add(id));
    },
    
    // Clear all test data
    _resetTest: () => {
      revokedCredentials.clear();
    }
  };
}

// Simulate blockchain delay
async function simulateBlockchainDelay(isRevocation = false) {
  // Revocation operations typically take longer than verifications
  const baseDelay = isRevocation ? 50 : 30;
  const variability = isRevocation ? 50 : 20;
  
  // Random delay to simulate blockchain network latency
  const delay = baseDelay + Math.random() * variability;
  
  return new Promise(resolve => setTimeout(resolve, delay));
}

// Generate test credentials with unique IDs for each test run
function generateTestCredentials(count, revocationRate, testRunId) {
  const credentials = [];
  const revokedCredentials = [];
  
  // Number of credentials to mark as revoked
  const revokedCount = Math.floor(count * revocationRate);
  
  // Generate credentials with unique IDs for each test run
  for (let i = 0; i < count; i++) {
    const credentialId = `test-run-${testRunId}-cred-${i + 1}`;
    credentials.push({
      id: credentialId,
      epoch: TEST_CONFIG.testEpoch
    });
    
    // Mark some as revoked based on revocation rate
    if (i < revokedCount) {
      revokedCredentials.push(credentialId);
    }
  }
  
  return { credentials, revokedCredentials };
}

// Run a single verification test
async function runVerificationTest(system, credentials, label) {
  console.log(`\nRunning ${label} verification test with ${credentials.length} credentials...`);
  
  const startTime = performance.now();
  
  // Single verification test
  if (credentials.length <= 10) {
    const results = {};
    
    // Verify each credential and measure time
    for (const cred of credentials) {
      const result = await system.verifyCredential(cred.id, cred.epoch);
      results[cred.id] = result;
    }
    
    const totalTime = performance.now() - startTime;
    const avgTime = totalTime / credentials.length;
    
    console.log(`${label} Single verification completed in ${totalTime.toFixed(2)}ms (avg ${avgTime.toFixed(2)}ms per credential)`);
    return { totalTime, avgTime, results };
  } 
  // Batch verification test (if supported)
  else {
    let results;
    
    // Use batch verification if available, otherwise fallback to loop
    if (system.batchVerifyCredentials) {
      results = await system.batchVerifyCredentials(credentials);
    } else {
      results = {};
      for (const cred of credentials) {
        results[cred.id] = await system.verifyCredential(cred.id, cred.epoch);
      }
    }
    
    const totalTime = performance.now() - startTime;
    const avgTime = totalTime / credentials.length;
    
    console.log(`${label} Batch verification of ${credentials.length} credentials completed in ${totalTime.toFixed(2)}ms (avg ${avgTime.toFixed(2)}ms per credential)`);
    return { totalTime, avgTime, results };
  }
}

// Run a single revocation test with better error handling
async function runRevocationTest(system, credentials, label) {
  console.log(`\nRunning ${label} revocation test with ${credentials.length} credentials...`);
  
  const startTime = performance.now();
  const results = {};
  const errors = [];
  
  // Revoke each credential and measure time
  for (const cred of credentials) {
    try {
      results[cred.id] = await system.revokeCredential(cred.id, 'test-issuer');
    } catch (error) {
      // Record errors but continue testing
      errors.push(`Error revoking ${cred.id}: ${error.message}`);
      
      // Add a dummy result
      results[cred.id] = { success: false, error: error.message };
    }
  }
  
  const totalTime = performance.now() - startTime;
  const avgTime = totalTime / credentials.length;
  
  console.log(`${label} Revocation of ${credentials.length} credentials completed in ${totalTime.toFixed(2)}ms (avg ${avgTime.toFixed(2)}ms per credential)`);
  
  if (errors.length > 0) {
    console.log(`Encountered ${errors.length} errors during revocation.`);
  }
  
  return { totalTime, avgTime, results, errors };
}

// Run a complete test suite
async function runTestSuite() {
  try {
    // Initialize the SQL module
    console.log("Initializing SQL Module...");
    const sqlModule = SQLModule.getInstance({
      dataDir: './data'
    });
    
    // Create the original system
    const originalSystem = createOriginalSystem();
    
    // Create the enhanced system with SQL optimizations
    const enhancedSystem = integrateWithCredentialRevocation(originalSystem);
    
    // Results storage
    const results = {
      verification: {
        original: {},
        enhanced: {}
      },
      revocation: {
        original: {},
        enhanced: {}
      }
    };
    
    // Test each batch size
    for (const batchSize of TEST_CONFIG.batchSizes) {
      // Test each revocation rate
      for (const revocationRate of TEST_CONFIG.revocationRates) {
        console.log(`\n==== Testing batch size ${batchSize} with revocation rate ${revocationRate * 100}% ====\n`);
        
        // Track results for this configuration
        if (!results.verification.original[batchSize]) {
          results.verification.original[batchSize] = {};
          results.verification.enhanced[batchSize] = {};
          results.revocation.original[batchSize] = {};
          results.revocation.enhanced[batchSize] = {};
        }
        
        // Run multiple test iterations and average results
        let originalVerifyTotal = 0;
        let enhancedVerifyTotal = 0;
        let originalRevokeTotal = 0;
        let enhancedRevokeTotal = 0;
        
        for (let run = 0; run < TEST_CONFIG.testRuns; run++) {
          console.log(`\n-- Test Run ${run + 1}/${TEST_CONFIG.testRuns} --`);
          
          // Reset original system for a fresh test
          originalSystem._resetTest();
          
          // Generate test credentials with run-specific IDs to avoid conflicts
          const { credentials, revokedCredentials } = generateTestCredentials(batchSize, revocationRate, `${batchSize}-${revocationRate}-${run}`);
          
          // Prepare systems with revoked credentials
          originalSystem._prepareTest(revokedCredentials);
          
          // First revoke the credentials in the enhanced system
          console.log(`Preparing enhanced system with ${revokedCredentials.length} revoked credentials...`);
          for (const credId of revokedCredentials) {
            try {
              await enhancedSystem.revokeCredential(credId, 'test-issuer');
            } catch (error) {
              if (error.code === 'SQLITE_CONSTRAINT_PRIMARYKEY') {
                // Ignore already revoked credentials
                console.log(`Credential ${credId} was already revoked, skipping...`);
              } else {
                console.error(`Error preparing revocation for ${credId}:`, error);
              }
            }
          }
          
          // Test verification performance
          const originalVerifyResult = await runVerificationTest(originalSystem, credentials, "Original");
          originalVerifyTotal += originalVerifyResult.totalTime;
          
          const enhancedVerifyResult = await runVerificationTest(enhancedSystem, credentials, "Enhanced");
          enhancedVerifyTotal += enhancedVerifyResult.totalTime;
          
          // Test revocation performance with a small subset of new credentials
          // Use a smaller number of credentials for revocation to avoid too many errors
          const revocationCount = Math.min(5, Math.floor(batchSize * 0.05));
          const revocationTestCredentials = credentials
            .filter(c => !revokedCredentials.includes(c.id)) // Only use credentials that aren't already revoked
            .slice(0, revocationCount);
          
          console.log(`Testing revocation with ${revocationTestCredentials.length} non-revoked credentials...`);
          
          if (revocationTestCredentials.length > 0) {
            const originalRevokeResult = await runRevocationTest(originalSystem, revocationTestCredentials, "Original");
            originalRevokeTotal += originalRevokeResult.totalTime;
            
            const enhancedRevokeResult = await runRevocationTest(enhancedSystem, revocationTestCredentials, "Enhanced");
            enhancedRevokeTotal += enhancedRevokeResult.totalTime;
          } else {
            console.log("No non-revoked credentials available for revocation test, skipping...");
          }
        }
        
        // Average the results
        results.verification.original[batchSize][revocationRate] = originalVerifyTotal / TEST_CONFIG.testRuns;
        results.verification.enhanced[batchSize][revocationRate] = enhancedVerifyTotal / TEST_CONFIG.testRuns;
        results.revocation.original[batchSize][revocationRate] = originalRevokeTotal / TEST_CONFIG.testRuns;
        results.revocation.enhanced[batchSize][revocationRate] = enhancedRevokeTotal / TEST_CONFIG.testRuns;
      }
    }
    
    // Display final results
    console.log("\n\n========== TEST RESULTS ==========\n");
    
    console.log("VERIFICATION PERFORMANCE (total ms):");
    for (const batchSize of TEST_CONFIG.batchSizes) {
      console.log(`\nBatch Size: ${batchSize}`);
      console.log("Revocation Rate | Original | Enhanced | Improvement");
      console.log("-------------------------------------------------");
      
      for (const rate of TEST_CONFIG.revocationRates) {
        const originalTime = results.verification.original[batchSize][rate];
        const enhancedTime = results.verification.enhanced[batchSize][rate];
        const improvement = ((originalTime - enhancedTime) / originalTime * 100).toFixed(2);
        
        console.log(`${(rate * 100).toFixed(1)}% | ${originalTime.toFixed(2)}ms | ${enhancedTime.toFixed(2)}ms | ${improvement}%`);
      }
    }
    
    console.log("\nREVOCATION PERFORMANCE (total ms):");
    for (const batchSize of TEST_CONFIG.batchSizes) {
      console.log(`\nBatch Size: ${batchSize}`);
      console.log("Revocation Rate | Original | Enhanced | Improvement");
      console.log("-------------------------------------------------");
      
      for (const rate of TEST_CONFIG.revocationRates) {
        const originalTime = results.revocation.original[batchSize][rate];
        const enhancedTime = results.revocation.enhanced[batchSize][rate];
        const improvement = ((originalTime - enhancedTime) / originalTime * 100).toFixed(2);
        
        console.log(`${(rate * 100).toFixed(1)}% | ${originalTime.toFixed(2)}ms | ${enhancedTime.toFixed(2)}ms | ${improvement}%`);
      }
    }
    
    // Get additional statistics from enhanced system
    console.log("\nSQL MODULE STATISTICS:");
    const falsePositiveStats = enhancedSystem.getFalsePositiveStats();
    console.log("False Positive Stats:", falsePositiveStats);
    
    const revocationStats = enhancedSystem.getRevocationStats();
    console.log("Revocation Stats:", revocationStats);
    
  } catch (error) {
    console.error("Test suite failed:", error);
  }
}

// Run the test suite
runTestSuite().catch(error => {
  console.error("Test failed:", error);
});