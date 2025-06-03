# Development Tests

These are basic functionality tests used during development to verify that individual components work. They are not comprehensive test suites.

## Purpose
- Verify SQLite connection works
- Test basic service functionality  
- Debug integration issues during development

## Running
```bash
node simple-sqlite-test.js
node simple-verification.test.js
node test-db.js
node test-integration.js
node test-revocation.js
node test-sql-integration.js
node test-verification.js

# etc.

## Development Tests
- `simple-sqlite-test.js` - Basic SQLite functionality
- `simple-verification-test.js` - Verification service basics 
- `test-db.js` - Database module loading
- `test-integration.js` - Integration testing
- `test-revocation.js` - Revocation service basics  
- `test-sql-integration.js` - Integration testing 
- `test-verification.js` - Verification service basics
