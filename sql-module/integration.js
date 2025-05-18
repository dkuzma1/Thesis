const SQLModule = require('./index');

/**
 * Integrates the SQL optimization module with Schumm's credential revocation architecture
 * @param {Object} originalSystem - The original credential revocation system
 * @param {Object} options - Configuration options
 * @returns {Object} Enhanced system with SQL optimizations
 */
function integrateWithCredentialRevocation(originalSystem, options = {}) {
  const sqlModule = SQLModule.getInstance(options);
  
  // Keep references to original methods
  const originalVerifyCredential = originalSystem.verifyCredential;
  const originalRevokeCredential = originalSystem.revokeCredential;
  
  // Enhanced system with SQL optimizations
  return {
    // Pass through other methods from original system
    ...originalSystem,
    
    /**
     * Enhanced credential verification with SQL optimizations
     * @param {string} credentialId - Credential ID
     * @param {number} issuanceEpoch - Issuance epoch
     * @param {...any} args - Additional arguments for original method
     * @returns {Object} Verification result
     */
    verifyCredential: async function(credentialId, issuanceEpoch, ...args) {
      try {
        // First run the original verification to get the bloom filter result
        const originalResult = await originalVerifyCredential.call(
          originalSystem,
          credentialId,
          issuanceEpoch,
          ...args
        );
        
        // Extract bloom filter result from original verification
        const bloomFilterResult = !originalResult;
        
        // Try to optimize using SQL
        const sqlResult = sqlModule.verifyCredential(
          credentialId,
          issuanceEpoch,
          bloomFilterResult
        );
        
        if (sqlResult !== null) {
          // SQL optimization successful
          return {
            ...sqlResult,
            optimized: true
          };
        }
        
        // Fall back to original result if SQL optimization fails
        return originalResult;
      } catch (error) {
        console.error('Error in enhanced verification:', error);
        // Fall back to original method on error
        return originalVerifyCredential.call(
          originalSystem,
          credentialId,
          issuanceEpoch,
          ...args
        );
      }
    },
    
    /**
     * Enhanced credential revocation with SQL optimizations
     * @param {string} credentialId - Credential ID
     * @param {string} issuerId - Issuer ID
     * @param {...any} args - Additional arguments for original method
     * @returns {Object} Revocation result
     */
    revokeCredential: async function(credentialId, issuerId, ...args) {
      try {
        // Call original revocation method
        const originalResult = await originalRevokeCredential.call(
          originalSystem,
          credentialId,
          issuerId,
          ...args
        );
        
        // Record in SQL for future optimization
        // Extract additional data from original result
        const revocationData = {
          credential_id: credentialId,
          issuer_id: issuerId,
          epoch_id: originalResult && originalResult.epochId ? originalResult.epochId : 1,
          prime_value: originalResult && originalResult.primeValue ? originalResult.primeValue : credentialId
        };
        
        sqlModule.recordRevocation(revocationData);
        
        return {
          ...originalResult,
          optimized: true
        };
      } catch (error) {
        console.error('Error in enhanced revocation:', error);
        // Fall back to original method on error
        return originalRevokeCredential.call(
          originalSystem,
          credentialId,
          issuerId,
          ...args
        );
      }
    },
    
    /**
     * Batch verify multiple credentials (new capability)
     * @param {Array} credentials - Array of credential objects
     * @returns {Object} Map of credential IDs to verification results
     */
    batchVerifyCredentials: async function(credentials) {
      try {
        const results = {};
        const credentialsWithBloomResults = [];
        
        // First, run original verification to get bloom filter results
        for (const cred of credentials) {
          const originalResult = await originalVerifyCredential.call(
            originalSystem,
            cred.id,
            cred.epoch
          );
          
          // Extract bloom filter result
          const bloomResult = !originalResult;
          
          credentialsWithBloomResults.push({
            ...cred,
            bloomResult,
            originalResult // Keep track of original result for comparison
          });
        }
        
        // Use SQL batch optimization
        const sqlResults = sqlModule.batchVerifyCredentials(credentialsWithBloomResults);
        
        if (sqlResults !== null) {
          // Process SQL results, but ensure they match original results
          for (const cred of credentialsWithBloomResults) {
            const sqlResult = sqlResults[cred.id];
            
            // Check for discrepancy
            if (sqlResult && cred.originalResult !== sqlResult.valid) {
              console.log(`Batch verification discrepancy for ${cred.id.substring(0, 8)}:`, 
                        `Original: ${cred.originalResult}, SQL: ${sqlResult.valid}`);
              
              // Use original result when discrepancy exists
              results[cred.id] = {
                valid: cred.originalResult,
                method: `${sqlResult.method}-discrepancy`,
                optimized: true,
                discrepancy: true
              };
            } else if (sqlResult) {
              // Results match, use SQL result
              results[cred.id] = {
                ...sqlResult,
                optimized: true
              };
            } else {
              // SQL didn't return a result for this credential
              results[cred.id] = {
                valid: cred.originalResult,
                method: 'original-fallback',
                optimized: false
              };
            }
          }
          
          return results;
        }
        
        // Fallback: If SQL batch fails, use individual verification
        for (const cred of credentials) {
          results[cred.id] = await this.verifyCredential(cred.id, cred.epoch);
        }
        
        return results;
      } catch (error) {
        console.error('Error in batch verification:', error);
        
        // Final fallback to individual verification
        const results = {};
        for (const cred of credentials) {
          results[cred.id] = await this.verifyCredential(cred.id, cred.epoch);
        }
        return results;
      }
    },
    
    /**
     * Create a batch for efficient processing of multiple revocations
     * @returns {Object} Batch information
     */
    createRevocationBatch: function() {
      const batchId = sqlModule.createRevocationBatch();
      return { batchId, createdAt: new Date().toISOString() };
    },
    
    /**
     * Add credentials to a revocation batch
     * @param {number} batchId - Batch ID
     * @param {Array} credentials - Array of credential objects
     * @returns {boolean} Success indicator
     */
    addToBatch: function(batchId, credentials) {
      return sqlModule.addToBatch(batchId, credentials);
    },
    
    /**
     * Process a revocation batch
     * @param {number} batchId - Batch ID
     * @returns {Object} Processing result
     */
    processBatch: async function(batchId) {
      // Process batch in SQL module first
      const sqlResult = sqlModule.processBatch(batchId);
      
      if (!sqlResult.success) {
        return sqlResult;
      }
      
      // Now process through original system if needed
      // This would depend on how the original system handles batch operations
      // For now, we just return the SQL result
      
      return sqlResult;
    },
    
    /**
     * Get statistics about false positives
     * @returns {Object} False positive statistics
     */
    getFalsePositiveStats: function() {
      return sqlModule.getFalsePositiveStats();
    },
    
    /**
     * Get statistics about revocations
     * @returns {Object} Revocation statistics
     */
    getRevocationStats: function() {
      return sqlModule.getRevocationStats();
    }
  };
}

module.exports = {
  integrateWithCredentialRevocation
};