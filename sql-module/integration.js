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
        const bloomFilterResult = !originalResult.valid;
        
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
          epoch_id: originalResult.epochId || 0,
          prime_value: originalResult.primeValue || ''
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
        // First get bloom filter results for all credentials
        const results = {};
        const credentialsWithBloomResults = [];
        
        // Process in batches to avoid overloading the system
        const batchSize = 50;
        for (let i = 0; i < credentials.length; i += batchSize) {
          const batch = credentials.slice(i, i + batchSize);
          
          // Get bloom filter results for the batch
          await Promise.all(batch.map(async (cred) => {
            try {
              const originalResult = await originalVerifyCredential.call(
                originalSystem,
                cred.id,
                cred.epoch
              );
              
              // Extract bloom filter result
              const bloomResult = !originalResult.valid;
              
              credentialsWithBloomResults.push({
                ...cred,
                bloomResult
              });
            } catch (error) {
              console.error(`Error checking bloom filter for credential ${cred.id}:`, error);
              // Don't add to the batch if we couldn't get a bloom filter result
            }
          }));
        }
        
        // Now optimize with SQL
        const sqlResults = sqlModule.batchVerifyCredentials(credentialsWithBloomResults);
        
        if (sqlResults !== null) {
          // Add optimization flag
          Object.keys(sqlResults).forEach(credId => {
            sqlResults[credId].optimized = true;
          });
          
          return sqlResults;
        }
        
        // Fall back to non-batch verification if SQL batch failed
        for (const cred of credentials) {
          results[cred.id] = await this.verifyCredential(cred.id, cred.epoch);
        }
        
        return results;
      } catch (error) {
        console.error('Error in batch verification:', error);
        
        // Fall back to non-batch verification
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