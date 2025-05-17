const path = require('path');
const { initDatabase, closeDatabase } = require('./database');
const VerificationService = require('./services/verificationService');
const RevocationService = require('./services/revocationService');

// Module instance
let sqlModule = null;

/**
 * SQLModule provides optimizations for credential revocation and verification
 */
class SQLModule {
  /**
   * Create a new SQLModule instance
   * @param {Object} options - Configuration options
   */
  constructor(options = {}) {
    const dataDir = options.dataDir || path.join(process.cwd(), 'data');
    initDatabase(dataDir);
    
    this.verificationService = new VerificationService();
    this.revocationService = new RevocationService();
  }

  /**
   * Get the SQLModule singleton instance
   * @param {Object} options - Configuration options
   * @returns {SQLModule} The SQLModule instance
   */
  static getInstance(options = {}) {
    if (!sqlModule) {
      sqlModule = new SQLModule(options);
    }
    return sqlModule;
  }

  /**
   * Shut down the SQLModule
   */
  shutdown() {
    closeDatabase();
    sqlModule = null;
  }

  /**
   * Optimize verification of a credential
   * @param {string} credentialId - ID of the credential to verify
   * @param {number} epochId - Epoch when the credential was issued
   * @param {boolean} bloomFilterResult - Result from Bloom filter check
   * @returns {Object} Verification result
   */
  verifyCredential(credentialId, epochId, bloomFilterResult) {
    return this.verificationService.verifyCredential(
      credentialId,
      epochId,
      bloomFilterResult
    );
  }

  /**
   * Batch verify multiple credentials
   * @param {Array} credentials - Array of credential objects
   * @returns {Object} Map of credential IDs to verification results
   */
  batchVerifyCredentials(credentials) {
    return this.verificationService.batchVerifyCredentials(credentials);
  }

  /**
   * Record a credential revocation
   * @param {Object} revocationData - Revocation data
   * @returns {boolean} Success indicator
   */
  recordRevocation(revocationData) {
    return this.revocationService.recordRevocation(revocationData);
  }

  /**
   * Create a batch for efficient processing of multiple revocations
   * @returns {number} Batch ID
   */
  createRevocationBatch() {
    return this.revocationService.createBatch();
  }

  /**
   * Add items to a revocation batch
   * @param {number} batchId - Batch ID
   * @param {Array} items - Array of revocation items
   * @returns {boolean} Success indicator
   */
  addToBatch(batchId, items) {
    return this.revocationService.addToBatch(batchId, items);
  }

  /**
   * Process a pending revocation batch
   * @param {number} batchId - Batch ID to process
   * @returns {Object} Processing result
   */
  processBatch(batchId) {
    return this.revocationService.processBatch(batchId);
  }

  /**
   * Get statistics about false positives
   * @returns {Object} False positive statistics
   */
  getFalsePositiveStats() {
    return this.verificationService.getFalsePositiveStats();
  }

  /**
   * Get statistics about revocations
   * @returns {Object} Revocation statistics
   */
  getRevocationStats() {
    return this.revocationService.getRevocationStats();
  }
}

module.exports = SQLModule;