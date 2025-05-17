const SQLModule = require('./index');  // Changed from './sql-module'
const { integrateWithCredentialRevocation } = require('./integration');  // Changed from './sql-module/integration'

async function testSQLIntegration() {
  try {
    console.log("Initializing SQL Module...");
    // Initialize SQL Module
    const sqlModule = SQLModule.getInstance({
      dataDir: './sql-module/data'
    });
    
    // Create a mock credential system with more realistic Bloom filter results
    const mockCredentialSystem = {
      verifyCredential: async (credentialId, issuanceEpoch) => {
        console.log(`[MOCK] Verifying credential: ${credentialId} from epoch ${issuanceEpoch}`);
        // Simulating a more accurate bloom filter result based on existing data
        // Assume "compromised-" credentials are in the bloom filter
        const bloomFilterResult = credentialId.includes("compromised-");
        return { 
          valid: !bloomFilterResult,
          method: "bloom-filter"
        };
      },
      
      revokeCredential: async (credentialId, issuerId) => {
        console.log(`[MOCK] Revoking credential: ${credentialId} from issuer ${issuerId}`);
        return { 
          success: true, 
          epochId: 3, 
          primeValue: `${credentialId}-prime-value`
        };
      }
    };
    
    // Integrate SQL optimization with mock system
    const enhancedSystem = integrateWithCredentialRevocation(mockCredentialSystem);
    
    console.log("\n--- Testing Enhanced Verification ---");
    
    // Try verifying a credential in the test data (already revoked)
    const revoked = await enhancedSystem.verifyCredential("compromised-cred-111", 3);
    console.log("Verification of revoked credential:", revoked);
    
    // Try verifying a credential that doesn't exist in the database
    const valid = await enhancedSystem.verifyCredential("valid-credential-999", 3);
    console.log("Verification of valid credential:", valid);
    
    console.log("\n--- Testing Enhanced Revocation ---");
    
    // Revoke a new credential
    const newRevocation = await enhancedSystem.revokeCredential("compromised-new", "test-issuer");
    console.log("Revocation result:", newRevocation);
    
    // Verify the newly revoked credential
    const newlyRevoked = await enhancedSystem.verifyCredential("compromised-new", 3);
    console.log("Verification of newly revoked credential:", newlyRevoked);
    
    console.log("\n--- Testing Batch Operations ---");
    
    // Test batch verification
    const batchResults = await enhancedSystem.batchVerifyCredentials([
      { id: "compromised-cred-222", epoch: 3 },
      { id: "valid-credential-888", epoch: 3 }
    ]);
    console.log("Batch verification results:", batchResults);
    
    console.log("\n--- System Statistics ---");
    
    // Get system statistics
    const falsePositiveStats = enhancedSystem.getFalsePositiveStats();
    console.log("False positive stats:", falsePositiveStats);
    
    const revocationStats = enhancedSystem.getRevocationStats();
    console.log("Revocation stats:", revocationStats);
    
  } catch (error) {
    console.error("Test failed:", error);
  }
}

// Run the test
testSQLIntegration();