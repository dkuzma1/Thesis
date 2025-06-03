// A simple test to verify that SQLite is working
const Database = require('better-sqlite3');

try {
  console.log('Creating a test SQLite database...');
  const db = new Database(':memory:'); // In-memory database
  
  console.log('Running a simple query...');
  const result = db.prepare('SELECT sqlite_version() as version').get();
  
  console.log(`SQLite version: ${result.version}`);
  
  db.close();
  console.log('Test completed successfully!');
} catch (error) {
  console.error('Error occurred:', error);
}