const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

// Database singleton instance
let db = null;

/**
 * Initialize the database
 * @param {string} dataDir - Directory where database file should be stored
 * @returns {Database} - Database instance
 */
function initDatabase(dataDir) {
  // Only initialize once
  if (db) return db;

  try {
    // Ensure data directory exists
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }

    // Connect to database
    const dbPath = path.join(dataDir, 'credential-optimizations.db');
    db = new Database(dbPath, { 
      verbose: process.env.NODE_ENV === 'development' ? console.log : null 
    });
    
    // Enable foreign keys
    db.pragma('foreign_keys = ON');
    
    // Create schemas
    createSchemas(db);
    
    console.log(`SQL module database initialized at ${dbPath}`);
    return db;
  } catch (err) {
    console.error('Failed to initialize database:', err);
    throw err;
  }
}

/**
 * Create database schemas
 * @param {Database} db - Database instance
 */
function createSchemas(db) {
  // Create tables in a transaction
  db.transaction(() => {
    // Table for definitive revocation records (helps with false positives)
    db.prepare(`
      CREATE TABLE IF NOT EXISTS DefinitiveRevocations (
        credential_id TEXT PRIMARY KEY,
        revocation_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        epoch_id INTEGER NOT NULL,
        issuer_id TEXT NOT NULL,
        prime_value TEXT NOT NULL
      )
    `).run();

    // Table for keeping track of known false positives
    db.prepare(`
      CREATE TABLE IF NOT EXISTS FalsePositives (
        credential_id TEXT NOT NULL,
        epoch_id INTEGER NOT NULL,
        detection_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        verification_count INTEGER NOT NULL DEFAULT 1,
        PRIMARY KEY (credential_id, epoch_id)
      )
    `).run();

    // Table for batch revocation operations
    db.prepare(`
      CREATE TABLE IF NOT EXISTS RevocationBatches (
        batch_id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        processed_at TIMESTAMP,
        item_count INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'pending'
      )
    `).run();

    // Table for batch revocation items
    db.prepare(`
      CREATE TABLE IF NOT EXISTS RevocationBatchItems (
        item_id INTEGER PRIMARY KEY AUTOINCREMENT,
        batch_id INTEGER NOT NULL,
        credential_id TEXT NOT NULL,
        prime_value TEXT NOT NULL,
        epoch_id INTEGER NOT NULL,
        issuer_id TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        FOREIGN KEY (batch_id) REFERENCES RevocationBatches(batch_id) ON DELETE CASCADE
      )
    `).run();

    // Table for performance analytics
    db.prepare(`
      CREATE TABLE IF NOT EXISTS PerformanceAnalytics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        epoch_id INTEGER NOT NULL,
        operation_type TEXT NOT NULL,
        execution_time_ms REAL NOT NULL,
        timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        false_positive_detected BOOLEAN DEFAULT 0
      )
    `).run();
  })();
}

/**
 * Close the database connection
 */
function closeDatabase() {
  if (db) {
    db.close();
    db = null;
    console.log('Database connection closed');
  }
}

/**
 * Get database instance
 * @returns {Database} Database instance
 */
function getDatabase() {
  if (!db) {
    throw new Error('Database not initialized. Call initDatabase first.');
  }
  return db;
}

module.exports = {
  initDatabase,
  closeDatabase,
  getDatabase
};