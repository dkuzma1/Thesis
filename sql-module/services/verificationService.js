const { performance } = require('perf_hooks');
const { getDatabase } = require('../database');
const BloomGuard = require('../utils/bloomGuard');

class VerificationService {
  constructor() {
    this.db = getDatabase();
    this.bloomGuard = new BloomGuard();
    this.prepareStatements();
  }

  /**
   * Prepare SQL statements for better performance
   */
  prepareStatements() {
    this.checkRevocation = this.db.prepare(
      'SELECT revocation_time FROM DefinitiveRevocations WHERE credential_id = ?'
    );
    
    this.checkFalsePositive = this.db.prepare(
      'SELECT verification_count FROM FalsePositives WHERE credential_id = ? AND epoch_id = ?'
    );
    
    this.updateFalsePositive = this.db.prepare(`
      UPDATE FalsePositives 
      SET verification_count = verification_count + 1 
      WHERE credential_id = ? AND epoch_id = ?
    `);
    
    this.insertFalsePositive = this.db.prepare(`
      INSERT INTO FalsePositives (credential_id, epoch_id) 
      VALUES (?, ?)
    `);
    
    this.recordAnalytics = this.db.prepare(`
      INSERT INTO PerformanceAnalytics (epoch_id, operation_type, execution_time_ms, false_positive_detected) 
      VALUES (?, ?, ?, ?)
    `);
  }

  /**
   * Optimized credential verification that guards against Bloom filter false positives
   * @param {string} credentialId - ID of the credential to verify
   * @param {number} epochId - Epoch ID when credential was issued
   * @param {boolean} bloomFilterResult - Result from Bloom filter (true if credential might be revoked)
   * @returns {Object} Verification result with method used
   */
  verifyCredential(credentialId, epochId, bloomFilterResult) {
    const startTime = performance.now();
    let falsePositive = false;
    
    try {
      // If Bloom filter says it's not revoked, it's definitely not revoked (no false negatives)
      if (!bloomFilterResult) {
        this.recordPerformance(epochId, 'verify-bloom-negative', startTime, false);
        return {
          valid: true,
          method: 'bloom-filter',
          checkedAt: new Date().toISOString()
        };
      }
      
      // Bloom filter says it might be revoked, check our definitive records
      const revoked = this.checkRevocation.get(credentialId);
      
      if (revoked) {
        // We have a definitive record of revocation
        this.recordPerformance(epochId, 'verify-sql-positive', startTime, false);
        return {
          valid: false,
          method: 'sql-definitive',
          revocationTime: revoked.revocation_time,
          checkedAt: new Date().toISOString()
        };
      }
      
      // Bloom filter says revoked but our DB says not revoked - this is a false positive
      falsePositive = true;
      
      // Check if we've seen this false positive before
      const fpRecord = this.checkFalsePositive.get(credentialId, epochId);
      
      if (fpRecord) {
        // We've seen this false positive before, update counter
        this.updateFalsePositive.run(credentialId, epochId);
        this.recordPerformance(epochId, 'verify-known-false-positive', startTime, true);
        return {
          valid: true,
          method: 'false-positive-cache',
          occurrences: fpRecord.verification_count + 1,
          checkedAt: new Date().toISOString()
        };
      } else {
        // This is a new false positive, record it
        this.insertFalsePositive.run(credentialId, epochId);
        this.recordPerformance(epochId, 'verify-new-false-positive', startTime, true);
        return {
          valid: true,
          method: 'new-false-positive',
          checkedAt: new Date().toISOString()
        };
      }
    } catch (error) {
      console.error('Optimized verification failed:', error);
      // If our verification fails, return null to indicate fallback to original method
      return null;
    }
  }

  /**
   * Batch verify multiple credentials efficiently
   * @param {Array<{id: string, epoch: number, bloomResult: boolean}>} credentials
   * @returns {Object} Map of credential IDs to verification results
   */
  batchVerifyCredentials(credentials) {
    const startTime = performance.now();
    const results = {};
    
    try {
      // Group credentials by their bloom filter result
      const credentialsByResult = {
        notRevoked: [],  // bloom filter says definitely not revoked
        potentiallyRevoked: [] // bloom filter says might be revoked
      };
      
      credentials.forEach(cred => {
        if (cred.bloomResult) {
          credentialsByResult.potentiallyRevoked.push(cred);
        } else {
          credentialsByResult.notRevoked.push(cred);
        }
      });
      
      // Process definitely not revoked credentials (no false negatives in bloom filters)
      credentialsByResult.notRevoked.forEach(cred => {
        results[cred.id] = {
          valid: true,
          method: 'bloom-filter',
          checkedAt: new Date().toISOString()
        };
      });
      
      // For potentially revoked credentials, check against our database
      if (credentialsByResult.potentiallyRevoked.length > 0) {
        // Prepare for batch DB queries
        const credIds = credentialsByResult.potentiallyRevoked.map(c => c.id);
        const placeholders = credIds.map(() => '?').join(',');
        
        // Check which credentials are definitely revoked
        const revokedRecords = this.db.prepare(`
          SELECT credential_id, revocation_time 
          FROM DefinitiveRevocations 
          WHERE credential_id IN (${placeholders})
        `).all(credIds);
        
        // Create lookup map of definitely revoked credentials
        const revokedMap = new Map();
        revokedRecords.forEach(r => {
          revokedMap.set(r.credential_id, r.revocation_time);
        });
        
        // Process each potentially revoked credential
        for (const cred of credentialsByResult.potentiallyRevoked) {
          if (revokedMap.has(cred.id)) {
            // Confirmed revoked
            results[cred.id] = {
              valid: false,
              method: 'sql-definitive',
              revocationTime: revokedMap.get(cred.id),
              checkedAt: new Date().toISOString()
            };
          } else {
            // False positive - check if we've seen it before
            const fpRecord = this.checkFalsePositive.get(cred.id, cred.epoch);
            
            if (fpRecord) {
              // Known false positive
              this.updateFalsePositive.run(cred.id, cred.epoch);
              results[cred.id] = {
                valid: true,
                method: 'false-positive-cache',
                occurrences: fpRecord.verification_count + 1,
                checkedAt: new Date().toISOString()
              };
            } else {
              // New false positive
              this.insertFalsePositive.run(cred.id, cred.epoch);
              results[cred.id] = {
                valid: true,
                method: 'new-false-positive',
                checkedAt: new Date().toISOString()
              };
            }
          }
        }
      }
      
      // Record overall batch performance
      this.recordPerformance(0, 'batch-verify', startTime, false);
      
      return results;
    } catch (error) {
      console.error('Batch verification failed:', error);
      return null; // Fallback to original method
    }
  }

  /**
   * Get statistics about false positives to help tune the system
   * @returns {Object} Statistics about false positives
   */
  getFalsePositiveStats() {
    return this.db.prepare(`
      SELECT 
        epoch_id, 
        COUNT(*) as total_false_positives,
        AVG(verification_count) as avg_occurrences,
        MAX(verification_count) as max_occurrences
      FROM FalsePositives
      GROUP BY epoch_id
      ORDER BY epoch_id
    `).all();
  }

  /**
   * Record performance metrics
   * @param {number} epochId - Epoch ID
   * @param {string} operationType - Type of operation
   * @param {number} startTime - Start time from performance.now()
   * @param {boolean} falsePositive - Whether a false positive was detected
   */
  recordPerformance(epochId, operationType, startTime, falsePositive) {
    const executionTime = performance.now() - startTime;
    this.recordAnalytics.run(epochId, operationType, executionTime, falsePositive ? 1 : 0);
  }
}

module.exports = VerificationService;