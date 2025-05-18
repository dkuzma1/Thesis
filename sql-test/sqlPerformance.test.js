// test/sqlPerformanceFixed.test.js
var bigInt = require("big-integer");
const { performance } = require('perf_hooks');

const { web3, assert, artifacts } = require("hardhat");
const { generateCredential } = require("../utilities/credential.js");
const { gen, hashToPrime } = require("../utilities/accumulator.js");
const { initBitmap, getBitmapData } = require("../utilities/bitmap.js");
const { emptyProducts, emptyStaticAccData } = require("../utilities/product");
const { revoke, verify } = require("../revocation/revocation");

// Import SQL module
const SQLModule = require("../sql-module");
const { integrateWithCredentialRevocation } = require("../sql-module/integration");

// Required contract artifacts
const DID = artifacts.require("DID");
const Cred = artifacts.require("Credentials");
const Admin = artifacts.require("AdminAccounts");
const Issuer = artifacts.require("IssuerRegistry");
const SubAcc = artifacts.require("SubAccumulator");
const Acc = artifacts.require("Accumulator");

describe("SQL-Enhanced Performance Test (Fixed)", function() {
    let accounts;
    let issuer;
    let issuer_Pri;
    
    // Contract instances
    let adminRegistryInstance;
    let issuerRegistryInstance;
    let didRegistryInstance;
    let credRegistryInstance;
    let subAccInstance;
    let accInstance;
    
    // Systems
    let originalSystem;
    let enhancedSystem;
    let sqlModule;
    
    // Test data
    const testSize = 30; // Number of credentials to test (smaller for faster tests)
    const revocationRate = 0.3; // 30% of credentials will be revoked
    let credentials = [];
    
    // Performance metrics
    const metrics = {
        original: {
            verification: {
                valid: [],      // Valid credentials
                revoked: []     // Revoked credentials
            },
            revocation: []
        },
        enhanced: {
            verification: {
                valid: [],      // Valid credentials
                revoked: []     // Revoked credentials
            },
            revocation: []
        }
    };
    
    before(async function() {
        this.timeout(300000); // 5 minute timeout for setup
        
        accounts = await web3.eth.getAccounts();
        
        // Create issuer account
        issuer_ = web3.eth.accounts.create();
        issuer_Pri = issuer_.privateKey;
        issuer = issuer_.address;
        
        console.log("Setting up contracts and data...");
        
        // Deploy contracts
        adminRegistryInstance = await Admin.new();
        issuerRegistryInstance = await Issuer.new(adminRegistryInstance.address);
        didRegistryInstance = await DID.new();
        credRegistryInstance = await Cred.new();
        subAccInstance = await SubAcc.new(issuerRegistryInstance.address);
        
        // Initialize bitmap with larger capacity
        await initBitmap(subAccInstance, 100);
        
        // Reset previous state
        emptyProducts();
        emptyStaticAccData();
        
        // Deploy global accumulator
        let [n, g] = gen();
        let nHex = "0x" + bigInt(n).toString(16);
        let gHex = "0x" + bigInt(g).toString(16);
        
        accInstance = await Acc.new(
            issuerRegistryInstance.address, 
            subAccInstance.address, 
            gHex, 
            nHex
        );
        
        // Add issuer to registry
        await issuerRegistryInstance.addIssuer(issuer);
        
        // Initialize SQL module
        console.log("Initializing SQL Module...");
        sqlModule = SQLModule.getInstance({
            dataDir: './sql-module/data'
        });
        
        // Create original credential system
        originalSystem = {
            verifyCredential: async (credentialId, epochId) => {
                return await verify(credentialId, epochId, subAccInstance, accInstance);
            },
            
            revokeCredential: async (credentialId, issuerId) => {
                await revoke(credentialId, subAccInstance, accInstance, issuer_Pri);
                
                return {
                    success: true,
                    epochId: 1,
                    primeValue: credentialId
                };
            }
        };
        
        // Create enhanced system with SQL optimizations
        enhancedSystem = integrateWithCredentialRevocation(originalSystem);
    });
    
    it('Should generate and revoke test credentials', async function() {
        this.timeout(60000); // 1 minute timeout
        
        // Generate test credentials
        console.log(`\nGenerating ${testSize} test credentials...`);
        const [bitmap, hashCount, count, capacity, epoch] = await getBitmapData(subAccInstance);
        
        for (let i = 0; i < testSize; i++) {
            const [credential, credentialHash, sig] = await generateCredential(
                `perf-test-${i}`, 
                issuer, 
                accounts[4], 
                "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC", 
                epoch.toNumber()
            );
            
            credentials.push({
                id: credentialHash,
                epoch: credential.epoch
            });
        }
        
        assert.equal(credentials.length, testSize, `Should have generated ${testSize} credentials`);
        
        // Revoke some credentials
        const toRevoke = Math.floor(testSize * revocationRate);
        console.log(`\nRevoking ${toRevoke} credentials...`);
        
        for (let i = 0; i < toRevoke; i++) {
            // First with original system and measure performance
            const origStart = performance.now();
            await originalSystem.revokeCredential(credentials[i].id, issuer);
            const origEnd = performance.now();
            metrics.original.revocation.push(origEnd - origStart);
            
            // Then with enhanced system and measure performance
            const enhStart = performance.now();
            await enhancedSystem.revokeCredential(credentials[i].id, issuer);
            const enhEnd = performance.now();
            metrics.enhanced.revocation.push(enhEnd - enhStart);
        }
        
        // Log revocation performance
        const origRevAvg = metrics.original.revocation.reduce((a, b) => a + b, 0) / 
                           metrics.original.revocation.length;
                           
        const enhRevAvg = metrics.enhanced.revocation.reduce((a, b) => a + b, 0) / 
                          metrics.enhanced.revocation.length;
        
        console.log(`\nRevocation performance:`);
        console.log(`Original system average: ${origRevAvg.toFixed(2)}ms`);
        console.log(`Enhanced system average: ${enhRevAvg.toFixed(2)}ms`);
        console.log(`Difference: ${(enhRevAvg - origRevAvg).toFixed(2)}ms (${((enhRevAvg - origRevAvg) / origRevAvg * 100).toFixed(2)}%)`);
    });
    
    it('Should verify revoked and valid credentials correctly', async function() {
        this.timeout(60000); // 1 minute timeout
        
        console.log("\nTesting verification performance...");
        
        // First, verify revoked credentials
        const revokedCount = Math.floor(testSize * revocationRate);
        console.log(`\nVerifying ${revokedCount} revoked credentials...`);
        
        // Verify each revoked credential with both systems
        for (let i = 0; i < revokedCount; i++) {
            const cred = credentials[i];
            
            // Original system
            const origStart = performance.now();
            const origResult = await originalSystem.verifyCredential(cred.id, cred.epoch);
            const origEnd = performance.now();
            metrics.original.verification.revoked.push(origEnd - origStart);
            
            // Enhanced system
            const enhStart = performance.now();
            const enhResult = await enhancedSystem.verifyCredential(cred.id, cred.epoch);
            const enhEnd = performance.now();
            metrics.enhanced.verification.revoked.push(enhEnd - enhStart);
            
            // Check if the results agree
            assert.equal(!origResult, !enhResult.valid, `Verification results should match for revoked credential ${i}`);
            assert.isFalse(origResult, `Original system should identify credential ${i} as revoked`);
            assert.isFalse(enhResult.valid, `Enhanced system should identify credential ${i} as revoked`);
        }
        
        // Next, verify valid credentials
        const validCount = Math.min(revokedCount, testSize - revokedCount); // Same number as revoked for fair comparison
        console.log(`\nVerifying ${validCount} valid credentials...`);
        
        // Verify each valid credential with both systems
        for (let i = 0; i < validCount; i++) {
            const index = revokedCount + i; // Start after revoked credentials
            const cred = credentials[index];
            
            // Original system
            const origStart = performance.now();
            const origResult = await originalSystem.verifyCredential(cred.id, cred.epoch);
            const origEnd = performance.now();
            metrics.original.verification.valid.push(origEnd - origStart);
            
            // Enhanced system
            const enhStart = performance.now();
            const enhResult = await enhancedSystem.verifyCredential(cred.id, cred.epoch);
            const enhEnd = performance.now();
            metrics.enhanced.verification.valid.push(enhEnd - enhStart);
            
            // Check if the results agree
            assert.equal(origResult, enhResult.valid, `Verification results should match for valid credential ${index}`);
            assert.isTrue(origResult, `Original system should identify credential ${index} as valid`);
            assert.isTrue(enhResult.valid, `Enhanced system should identify credential ${index} as valid`);
        }
        
        // Log verification performance
        // For revoked credentials
        const origRevokedAvg = metrics.original.verification.revoked.reduce((a, b) => a + b, 0) / 
                              metrics.original.verification.revoked.length;
                              
        const enhRevokedAvg = metrics.enhanced.verification.revoked.reduce((a, b) => a + b, 0) / 
                             metrics.enhanced.verification.revoked.length;
        
        console.log(`\nRevoked credential verification performance:`);
        console.log(`Original system average: ${origRevokedAvg.toFixed(2)}ms`);
        console.log(`Enhanced system average: ${enhRevokedAvg.toFixed(2)}ms`);
        console.log(`Difference: ${(enhRevokedAvg - origRevokedAvg).toFixed(2)}ms (${((enhRevokedAvg - origRevokedAvg) / origRevokedAvg * 100).toFixed(2)}%)`);
        
        // For valid credentials
        const origValidAvg = metrics.original.verification.valid.reduce((a, b) => a + b, 0) / 
                             metrics.original.verification.valid.length;
                             
        const enhValidAvg = metrics.enhanced.verification.valid.reduce((a, b) => a + b, 0) / 
                            metrics.enhanced.verification.valid.length;
        
        console.log(`\nValid credential verification performance:`);
        console.log(`Original system average: ${origValidAvg.toFixed(2)}ms`);
        console.log(`Enhanced system average: ${enhValidAvg.toFixed(2)}ms`);
        console.log(`Difference: ${(enhValidAvg - origValidAvg).toFixed(2)}ms (${((enhValidAvg - origValidAvg) / origValidAvg * 100).toFixed(2)}%)`);
    });
    
    it('Should efficiently perform batch verification', async function() {
        this.timeout(60000); // 1 minute timeout
        
        console.log("\nTesting batch verification performance...");
        
        // Test with batch size of 10 credentials (mix of revoked and valid)
        const batchSize = 10;
        console.log(`\nBatch size: ${batchSize}`);
        
        // Create batch
        const halfSize = Math.floor(batchSize / 2);
        const batch = [
            ...credentials.slice(0, halfSize),                      // Revoked
            ...credentials.slice(Math.floor(testSize * revocationRate), Math.floor(testSize * revocationRate) + halfSize) // Valid
        ];
        
        // Original system (one by one)
        const origStart = performance.now();
        const origResults = {};
        
        for (const cred of batch) {
            origResults[cred.id] = await originalSystem.verifyCredential(cred.id, cred.epoch);
        }
        
        const origEnd = performance.now();
        const origTime = origEnd - origStart;
        
        // Enhanced system (batch)
        const enhStart = performance.now();
        const enhResults = await enhancedSystem.batchVerifyCredentials(batch);
        const enhEnd = performance.now();
        const enhTime = enhEnd - enhStart;
        
        // Verify results match for all credentials
        let matchCount = 0;
        for (const cred of batch) {
            if (origResults[cred.id] === enhResults[cred.id].valid) {
                matchCount++;
            } else {
                console.log(`Mismatch for credential ${cred.id.substring(0, 8)}... - Original: ${origResults[cred.id]}, Enhanced: ${enhResults[cred.id].valid}`);
            }
        }
        
        console.log(`\nBatch verification performance:`);
        console.log(`Original system total: ${origTime.toFixed(2)}ms (${(origTime / batchSize).toFixed(2)}ms per credential)`);
        console.log(`Enhanced system total: ${enhTime.toFixed(2)}ms (${(enhTime / batchSize).toFixed(2)}ms per credential)`);
        console.log(`Difference: ${(enhTime - origTime).toFixed(2)}ms (${((enhTime - origTime) / origTime * 100).toFixed(2)}%)`);
        console.log(`Results match: ${matchCount}/${batchSize} (${(matchCount / batchSize * 100).toFixed(2)}%)`);
        
        assert.equal(matchCount, batchSize, `All batch verification results should match (got ${matchCount}/${batchSize})`);
    });
    
    it('Should assess repeated verification performance benefit', async function() {
        this.timeout(60000); // 1 minute timeout
        
        console.log("\nTesting repeated verification performance (caching benefit)...");
        
        // Select 5 credentials to repeatedly verify
        const testCredentials = [
            ...credentials.slice(0, 2),  // Revoked
            ...credentials.slice(Math.floor(testSize * revocationRate), Math.floor(testSize * revocationRate) + 3)  // Valid
        ];
        
        // First pass verification times
        const originalFirstPass = [];
        const enhancedFirstPass = [];
        
        // Second pass verification times
        const originalSecondPass = [];
        const enhancedSecondPass = [];
        
        // First pass
        console.log("\nFirst verification pass:");
        for (const cred of testCredentials) {
            // Original system
            const origStart = performance.now();
            await originalSystem.verifyCredential(cred.id, cred.epoch);
            const origEnd = performance.now();
            originalFirstPass.push(origEnd - origStart);
            
            // Enhanced system
            const enhStart = performance.now();
            await enhancedSystem.verifyCredential(cred.id, cred.epoch);
            const enhEnd = performance.now();
            enhancedFirstPass.push(enhEnd - enhStart);
        }
        
        // Second pass (repeated verification)
        console.log("\nSecond verification pass (repeated):");
        for (const cred of testCredentials) {
            // Original system
            const origStart = performance.now();
            await originalSystem.verifyCredential(cred.id, cred.epoch);
            const origEnd = performance.now();
            originalSecondPass.push(origEnd - origStart);
            
            // Enhanced system
            const enhStart = performance.now();
            await enhancedSystem.verifyCredential(cred.id, cred.epoch);
            const enhEnd = performance.now();
            enhancedSecondPass.push(enhEnd - enhStart);
        }
        
        // Calculate averages
        const origFirstAvg = originalFirstPass.reduce((a, b) => a + b, 0) / originalFirstPass.length;
        const enhFirstAvg = enhancedFirstPass.reduce((a, b) => a + b, 0) / enhancedFirstPass.length;
        const origSecondAvg = originalSecondPass.reduce((a, b) => a + b, 0) / originalSecondPass.length;
        const enhSecondAvg = enhancedSecondPass.reduce((a, b) => a + b, 0) / enhancedSecondPass.length;
        
        console.log(`\nFirst pass performance:`);
        console.log(`Original system average: ${origFirstAvg.toFixed(2)}ms`);
        console.log(`Enhanced system average: ${enhFirstAvg.toFixed(2)}ms`);
        
        console.log(`\nSecond pass performance (repeated verification):`);
        console.log(`Original system average: ${origSecondAvg.toFixed(2)}ms`);
        console.log(`Enhanced system average: ${enhSecondAvg.toFixed(2)}ms`);
        
        // Compare enhancements between first and second pass
        const origImprovement = (origFirstAvg - origSecondAvg) / origFirstAvg * 100;
        const enhImprovement = (enhFirstAvg - enhSecondAvg) / enhFirstAvg * 100;
        
        console.log(`\nImprovement from first to second pass:`);
        console.log(`Original system: ${origImprovement.toFixed(2)}%`);
        console.log(`Enhanced system: ${enhImprovement.toFixed(2)}%`);
        
        // The enhanced system should show greater improvement in the second pass due to caching
        console.log(`\nEnhanced system should show greater improvement due to caching: ${enhImprovement.toFixed(2)}% vs ${origImprovement.toFixed(2)}%`);
    });
    
    after(function() {
        // Final performance summary
        console.log("\n=== PERFORMANCE SUMMARY ===");
        
        // Revocation
        const origRevAvg = metrics.original.revocation.reduce((a, b) => a + b, 0) / 
                           metrics.original.revocation.length;
                           
        const enhRevAvg = metrics.enhanced.revocation.reduce((a, b) => a + b, 0) / 
                          metrics.enhanced.revocation.length;
        
        console.log(`\nRevocation Performance:`);
        console.log(`Original system: ${origRevAvg.toFixed(2)}ms`);
        console.log(`Enhanced system: ${enhRevAvg.toFixed(2)}ms`);
        console.log(`Difference: ${(enhRevAvg - origRevAvg).toFixed(2)}ms (${((enhRevAvg - origRevAvg) / origRevAvg * 100).toFixed(2)}%)`);
        
        // Verification performance for valid credentials
        const origValidAvg = metrics.original.verification.valid.reduce((a, b) => a + b, 0) / 
                             metrics.original.verification.valid.length;
                             
        const enhValidAvg = metrics.enhanced.verification.valid.reduce((a, b) => a + b, 0) / 
                            metrics.enhanced.verification.valid.length;
        
        console.log(`\nValid Credential Verification Performance:`);
        console.log(`Original system: ${origValidAvg.toFixed(2)}ms`);
        console.log(`Enhanced system: ${enhValidAvg.toFixed(2)}ms`);
        console.log(`Difference: ${(enhValidAvg - origValidAvg).toFixed(2)}ms (${((enhValidAvg - origValidAvg) / origValidAvg * 100).toFixed(2)}%)`);
        
        // Verification performance for revoked credentials
        const origRevokedAvg = metrics.original.verification.revoked.reduce((a, b) => a + b, 0) / 
                              metrics.original.verification.revoked.length;
                              
        const enhRevokedAvg = metrics.enhanced.verification.revoked.reduce((a, b) => a + b, 0) / 
                             metrics.enhanced.verification.revoked.length;
        
        console.log(`\nRevoked Credential Verification Performance:`);
        console.log(`Original system: ${origRevokedAvg.toFixed(2)}ms`);
        console.log(`Enhanced system: ${enhRevokedAvg.toFixed(2)}ms`);
        console.log(`Difference: ${(enhRevokedAvg - origRevokedAvg).toFixed(2)}ms (${((enhRevokedAvg - origRevokedAvg) / origRevokedAvg * 100).toFixed(2)}%)`);
        
        // Get SQL module stats
        console.log("\nSQL Module Statistics:");
        console.log(enhancedSystem.getRevocationStats());
    });
});