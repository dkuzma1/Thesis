const { performance } = require('perf_hooks');
const { getDatabase } = require('../database');

class RevocationService {
  constructor() {
    this.db = getDatabase();
    this.prepareStatements();
  }

  /**
   //Prepare SQL statements for better performance
   */
  prepareStatements() {
    this.insertRevocation = this.db.prepare(`
      INSERT INTO DefinitiveRevocations (credential_id, epoch_id, issuer_id, prime_value)
      VALUES (?, ?, ?, ?)
    `);
    
    this.createRevocationBatch = this.db.prepare(`
      INSERT INTO RevocationBatches DEFAULT VALUES
    `);
    
    this.addBatchItem = this.db.prepare(`
      INSERT INTO RevocationBatchItems (batch_id, credential_id, prime_value, epoch_id, issuer_id)
      VALUES (?, ?, ?, ?, ?)
    `);
    
    this.updateBatchCount = this.db.prepare(`
      UPDATE RevocationBatches SET item_count = item_count + ? WHERE batch_id = ?
    `);
    
    this.markBatchProcessed = this.db.prepare(`
      UPDATE RevocationBatches 
      SET status = 'processed', processed_at = CURRENT_TIMESTAMP 
      WHERE batch_id = ?
    `);
    
    this.markBatchItemProcessed = this.db.prepare(`
      UPDATE RevocationBatchItems SET status = 'processed' WHERE batch_id = ?
    `);
    
    this.getPendingBatches = this.db.prepare(`
      SELECT * FROM RevocationBatches WHERE status = 'pending' ORDER BY created_at
    `);
    
    this.getBatchItems = this.db.prepare(`
      SELECT * FROM RevocationBatchItems WHERE batch_id = ? ORDER BY item_id
    `);
    
    this.recordAnalytics = this.db.prepare(`
      INSERT INTO PerformanceAnalytics (epoch_id, operation_type, execution_time_ms)
      VALUES (?, ?, ?)
    `);
  }

  /**
   //Record a revocation in our definitive records
   * @param {Object} revocationData - Revocation data
   * @returns {boolean} Success indicator
   */
  recordRevocation(revocationData) {
    const { credential_id, epoch_id, issuer_id, prime_value } = revocationData;
    const startTime = performance.now();
    
    try {
      this.insertRevocation.run(credential_id, epoch_id, issuer_id, prime_value);
      
      // Clean up any false positive records for this credential
      this.db.prepare(`
        DELETE FROM FalsePositives WHERE credential_id = ?
      `).run(credential_id);
      
      this.recordPerformance(epoch_id, 'revocation', startTime);
      return true;
    } catch (error) {
      if (error.code === 'SQLITE_CONSTRAINT') {
        // Already revoked, not an error
        return true;
      }
      console.error('Failed to record revocation:', error);
      return false;
    }
  }

  /**
   //Create a batch for efficient processing of multiple revocations
   * @returns {number} Batch ID
   */
  createBatch() {
    const result = this.createRevocationBatch.run();
    return result.lastInsertRowid;
  }

  /**
   //Add items to a revocation batch
   * @param {number} batchId - Batch ID
   * @param {Array} items - Array of revocation items
   * @returns {boolean} Success indicator
   */
  addToBatch(batchId, items) {
    try {
      // Use a transaction for atomicity
      this.db.transaction(() => {
        for (const item of items) {
          this.addBatchItem.run(
            batchId,
            item.credential_id,
            item.prime_value,
            item.epoch_id,
            item.issuer_id
          );
        }
        this.updateBatchCount.run(items.length, batchId);
      })();
      
      return true;
    } catch (error) {
      console.error('Failed to add items to batch:', error);
      return false;
    }
  }

  /**
   //Process a pending batch, efficiently revoking credentials
   * @param {number} batchId - Batch ID to process
   * @returns {Object} Processing result with timing info
   */
  processBatch(batchId) {
    const startTime = performance.now();
    
    try {
      // Get all items in the batch
      const items = this.getBatchItems.all(batchId);
      
      if (items.length === 0) {
        return {
          success: false,
          error: 'No items in batch',
          executionTime: performance.now() - startTime
        };
      }
      
      // Group by epoch for efficient processing
      const itemsByEpoch = {};
      items.forEach(item => {
        if (!itemsByEpoch[item.epoch_id]) {
          itemsByEpoch[item.epoch_id] = [];
        }
        itemsByEpoch[item.epoch_id].push(item);
      });
      
      // Process each epoch group
      // In a real implementation, you might use a more complex grouping logic
      for (const [epochId, epochItems] of Object.entries(itemsByEpoch)) {
        // Record timing for each epoch separately
        const epochStartTime = performance.now();
        
        // Process all items in this epoch
        // Record them in our definitive revocations
        this.db.transaction(() => {
          for (const item of epochItems) {
            this.insertRevocation.run(
              item.credential_id,
              item.epoch_id,
              item.issuer_id,
              item.prime_value
            );
          }
        })();
        
        this.recordPerformance(
          parseInt(epochId, 10),
          'batch-revocation',
          epochStartTime
        );
      }
      
      // Mark the batch as processed
      this.markBatchProcessed.run(batchId);
      this.markBatchItemProcessed.run(batchId);
      
      return {
        success: true,
        itemCount: items.length,
        executionTime: performance.now() - startTime
      };
    } catch (error) {
      console.error('Failed to process batch:', error);
      return {
        success: false,
        error: error.message,
        executionTime: performance.now() - startTime
      };
    }
  }

  /**
   * Get all pending revocation batches
   * @returns {Array} Pending batches
   */
  getPendingBatches() {
    return this.getPendingBatches.all();
  }

  /**
   * Get comprehensive revocation statistics
   * @returns {Object} Revocation statistics
   */
  getRevocationStats() {
    return {
      totalRevocations: this.db.prepare('SELECT COUNT(*) as count FROM DefinitiveRevocations').get().count,
      
      revocationsByEpoch: this.db.prepare(`
        SELECT epoch_id, COUNT(*) as count 
        FROM DefinitiveRevocations 
        GROUP BY epoch_id 
        ORDER BY epoch_id
      `).all(),
      
      batchStats: this.db.prepare(`
        SELECT 
          COUNT(*) as total_batches,
          SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_batches,
          SUM(CASE WHEN status = 'processed' THEN 1 ELSE 0 END) as processed_batches,
          SUM(item_count) as total_items,
          AVG(item_count) as avg_batch_size
        FROM RevocationBatches
      `).get(),
      
      performanceMetrics: this.db.prepare(`
        SELECT 
          operation_type,
          COUNT(*) as operation_count,
          AVG(execution_time_ms) as avg_execution_time,
          MIN(execution_time_ms) as min_execution_time,
          MAX(execution_time_ms) as max_execution_time
        FROM PerformanceAnalytics
        GROUP BY operation_type
      `).all()
    };
  }

  /**
   * Record performance metrics
   * @param {number} epochId - Epoch ID
   * @param {string} operationType - Type of operation
   * @param {number} startTime - Start time from performance.now()
   */
  recordPerformance(epochId, operationType, startTime) {
    const executionTime = performance.now() - startTime;
    this.recordAnalytics.run(epochId, operationType, executionTime);
  }
}

module.exports = RevocationService;