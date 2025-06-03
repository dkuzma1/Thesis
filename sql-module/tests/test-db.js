const path = require('path');

try {
  console.log('Attempting to load database module...');
  const { initDatabase, closeDatabase } = require('../database');
  
  // Test database functionality
  console.log('Testing database module...');
  
  // Initialize database in a test directory
  const testDataDir = path.join(__dirname, 'test-data');
  console.log(`Using test data directory: ${testDataDir}`);
  
  const db = initDatabase(testDataDir);
  console.log('Database initialized successfully');
  
  // Verify we can perform a simple query
  console.log('Executing test query...');
  const result = db.prepare('SELECT sqlite_version() as version').get();
  console.log(`SQLite version: ${result.version}`);
  
  // Close database
  closeDatabase();
  console.log('Database closed successfully');
  
  console.log('Database test completed successfully!');
} catch (error) {
  console.error('ERROR OCCURRED:', error);
  console.error('Stack trace:', error.stack);
}