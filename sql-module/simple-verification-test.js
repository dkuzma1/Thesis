const path = require('path');

console.log('Starting simple verification test...');

try {
  // Step 1: Load the database module
  console.log('1. Loading database module...');
  const { initDatabase, closeDatabase } = require('./database');
  console.log('   Database module loaded successfully');
  
  // Step 2: Initialize the database
  console.log('2. Initializing database...');
  const testDataDir = path.join(__dirname, 'test-data');
  initDatabase(testDataDir);
  console.log('   Database initialized successfully');
  
  // Step 3: Try to load the BloomGuard utility
  console.log('3. Loading BloomGuard utility...');
  const BloomGuard = require('./utils/bloomGuard');
  console.log('   BloomGuard loaded successfully');
  
  // Step 4: Create an instance of BloomGuard
  console.log('4. Creating BloomGuard instance...');
  const bloomGuard = new BloomGuard();
  console.log('   BloomGuard instance created successfully');
  
  // Step 5: Try to load the VerificationService
  console.log('5. Loading VerificationService...');
  const VerificationService = require('./services/verificationService');
  console.log('   VerificationService loaded successfully');
  
  // Step 6: Create an instance of VerificationService
  console.log('6. Creating VerificationService instance...');
  const verificationService = new VerificationService();
  console.log('   VerificationService instance created successfully');
  
  // Step 7: Try a simple verification
  console.log('7. Testing simple verification...');
  const result = verificationService.verifyCredential('test-credential', 1, false);
  console.log('   Verification result:', result);
  
  // Close database
  closeDatabase();
  
  console.log('Test completed successfully!');
} catch (error) {
  console.error('ERROR:', error);
  console.error('Stack trace:', error.stack);
}