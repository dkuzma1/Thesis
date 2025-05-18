var bigInt = require("big-integer");
const { performance } = require('perf_hooks');

const { web3, assert, artifacts } = require("hardhat");
const { generateCredential } = require("../utilities/credential.js");
const { gen, hashToPrime } = require("../utilities/accumulator.js");
const { initBitmap, getBitmapData, getStaticAccData, checkInclusionBitmap } = require("../utilities/bitmap.js");
const { emptyProducts, emptyStaticAccData } = require("../utilities/product.js");
const { revoke, verify } = require("../revocation/revocation.js");

// Import SQL module
const SQLModule = require("../sql-module/index.js");
const { integrateWithCredentialRevocation } = require("../sql-module/integration.js");

// Required contract artifacts
const DID = artifacts.require("DID");
const Cred = artifacts.require("Credentials");
const Admin = artifacts.require("AdminAccounts");
const Issuer = artifacts.require("IssuerRegistry");
const SubAcc = artifacts.require("SubAccumulator");
const Acc = artifacts.require("Accumulator");

describe("SQL-Enhanced Credential Revocation System", function() {
    let accounts;
    let holder;
    let issuer;
    
    let issuer_;
    let issuer_Pri;
    
    // bitmap capacity
    let capacity = 30;
    
    // contract instances
    let adminRegistryInstance;
    let issuerRegistryInstance;
    let didRegistryInstance;
    let credRegistryInstance;
    let subAccInstance;
    let accInstance;
    
    // SQL-enhanced system
    let sqlModule;
    let originalSystem;
    let enhancedSystem;
    
    // Test data
    let credentials = [];
    let epochs = [];
    
    // Performance metrics
    let metrics = {
        original: {
            verification: [],
            revocation: []
        },
        enhanced: {
            verification: [],
            revocation: []
        }
    };
    
    before(async function() {
        accounts = await web3.eth.getAccounts();
        holder = accounts[1];
        
        // Create issuer account with public/private keys
        issuer_ = web3.eth.accounts.create();
        issuer_Pri = issuer_.privateKey;
        issuer = issuer_.address;
        
        // Initialize SQL module
        console.log("Initializing SQL Module...");
        sqlModule = SQLModule.getInstance({
            dataDir: './sql-module/data'
        });
        
        // Increase timeout for these tests
        this.timeout(100000);
    });
    
    describe("Setup", function() {
        it('Deploying contracts', async() => {
            // Deploy Admin registry
            adminRegistryInstance = await Admin.new();
            
            // Deploy Issuer registry
            issuerRegistryInstance = await Issuer.new(adminRegistryInstance.address);
            
            // Deploy DID registry
            didRegistryInstance = await DID.new();
            
            // Deploy Credential registry
            credRegistryInstance = await Cred.new();
            
            // Deploy and initialize bitmap
            subAccInstance = await SubAcc.new(issuerRegistryInstance.address);
            await initBitmap(subAccInstance, capacity);
            
            // Clean up from previous tests
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
            
            // Create original credential system
            originalSystem = {
                verifyCredential: async (credentialId, epochId) => {
                    return await verify(credentialId, epochId, subAccInstance, accInstance);
                },
                
                revokeCredential: async (credentialId, issuerId) => {
                    return await revoke(credentialId, subAccInstance, accInstance, issuer_Pri);
                }
            };
            
            // Create enhanced system with SQL optimizations
            enhancedSystem = integrateWithCredentialRevocation(originalSystem);
        });
    });
    
    describe("Credential Operations", function() {
        function makeid(length) {
            var result = '';
            var characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
            var charactersLength = characters.length;
            for (var i = 0; i < length; i++) {
                result += characters.charAt(Math.floor(Math.random() * charactersLength));
            }
            return result;
        }
        
        it('Issuing credentials', async() => {
            // Generate test credentials
            for (let i = 0; i < 30; i++) {
                let item = makeid(5);
                let [currentBitmap, hashCount, count, capacity, currentEpoch] = await getBitmapData(subAccInstance);
                
                // Generate credential
                let [credential, credentialHash, sig] = await generateCredential(
                    item, 
                    issuer, 
                    accounts[4], 
                    "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC", 
                    currentEpoch.toNumber()
                );
                
                // Convert to prime
                let [credentialPrime, nonce] = hashToPrime(credentialHash, 128, 0n);
                
                // Store for later use
                credentials.push([credentialHash, credentialPrime]);
                epochs.push(credential.epoch);
            }
            
            assert.equal(30, credentials.length, "Should have generated 30 credentials");
        });
        
        it('Revoking credentials', async() => {
            // Revoke first 10 credentials with both systems
            for (let i = 0; i < 10; i++) {
                // Get the credential to revoke
                let [credHash, credPrime] = credentials[i];
                
                // Revoke with original system and measure time
                let origStart = performance.now();
                await originalSystem.revokeCredential(credHash, issuer);
                let origEnd = performance.now();
                metrics.original.revocation.push(origEnd - origStart);
                
                // Revoke with enhanced system and measure time
                let enhStart = performance.now();
                await enhancedSystem.revokeCredential(credHash, issuer);
                let enhEnd = performance.now();
                metrics.enhanced.revocation.push(enhEnd - enhStart);
            }
            
            // Log average revocation times
            const origAvg = metrics.original.revocation.reduce((a, b) => a + b, 0) / metrics.original.revocation.length;
            const enhAvg = metrics.enhanced.revocation.reduce((a, b) => a + b, 0) / metrics.enhanced.revocation.length;
            
            console.log(`Original revocation avg: ${origAvg.toFixed(2)}ms`);
            console.log(`Enhanced revocation avg: ${enhAvg.toFixed(2)}ms`);
            console.log(`Improvement: ${((origAvg - enhAvg) / origAvg * 100).toFixed(2)}%`);
        });
        
        it('Verifying valid credentials (not revoked)', async() => {
            // Verify credentials that weren't revoked (indices 10-19)
            for (let i = 10; i < 20; i++) {
                let [credHash, credPrime] = credentials[i];
                let epoch = epochs[i];
                
                // Verify with original system and measure time
                let origStart = performance.now();
                let origResult = await originalSystem.verifyCredential(credHash, epoch);
                let origEnd = performance.now();
                metrics.original.verification.push(origEnd - origStart);
                
                // Verify with enhanced system and measure time
                let enhStart = performance.now();
                let enhResult = await enhancedSystem.verifyCredential(credHash, epoch);
                let enhEnd = performance.now();
                metrics.enhanced.verification.push(enhEnd - enhStart);
                
                // Results should match
                assert.equal(
                    origResult, 
                    enhResult.valid, 
                    `Verification results should match for credential ${i}`
                );
                
                // Credential should be valid
                assert.isTrue(origResult, `Credential ${i} should be valid`);
                assert.isTrue(enhResult.valid, `Enhanced credential ${i} should be valid`);
            }
            
            // Log average verification times
            const origAvg = metrics.original.verification.reduce((a, b) => a + b, 0) / metrics.original.verification.length;
            const enhAvg = metrics.enhanced.verification.reduce((a, b) => a + b, 0) / metrics.enhanced.verification.length;
            
            console.log(`Original verification avg (valid creds): ${origAvg.toFixed(2)}ms`);
            console.log(`Enhanced verification avg (valid creds): ${enhAvg.toFixed(2)}ms`);
            console.log(`Improvement: ${((origAvg - enhAvg) / origAvg * 100).toFixed(2)}%`);
        });
        
        it('Verifying revoked credentials', async() => {
            // Reset verification metrics
            metrics.original.verification = [];
            metrics.enhanced.verification = [];
            
            // Verify credentials that were revoked (indices 0-9)
            for (let i = 0; i < 10; i++) {
                let [credHash, credPrime] = credentials[i];
                let epoch = epochs[i];
                
                // Verify with original system and measure time
                let origStart = performance.now();
                let origResult = await originalSystem.verifyCredential(credHash, epoch);
                let origEnd = performance.now();
                metrics.original.verification.push(origEnd - origStart);
                
                // Verify with enhanced system and measure time
                let enhStart = performance.now();
                let enhResult = await enhancedSystem.verifyCredential(credHash, epoch);
                let enhEnd = performance.now();
                metrics.enhanced.verification.push(enhEnd - enhStart);
                
                // Results should match
                assert.equal(
                    origResult, 
                    enhResult.valid, 
                    `Verification results should match for revoked credential ${i}`
                );
                
                // Credential should be invalid (revoked)
                assert.isFalse(origResult, `Credential ${i} should be revoked`);
                assert.isFalse(enhResult.valid, `Enhanced credential ${i} should be revoked`);
                
                // Enhanced result should use SQL-definitive method
                assert.equal(
                    enhResult.method, 
                    "sql-definitive", 
                    `Enhanced system should use SQL-definitive method for revoked credential ${i}`
                );
            }
            
            // Log average verification times
            const origAvg = metrics.original.verification.reduce((a, b) => a + b, 0) / metrics.original.verification.length;
            const enhAvg = metrics.enhanced.verification.reduce((a, b) => a + b, 0) / metrics.enhanced.verification.length;
            
            console.log(`Original verification avg (revoked creds): ${origAvg.toFixed(2)}ms`);
            console.log(`Enhanced verification avg (revoked creds): ${enhAvg.toFixed(2)}ms`);
            console.log(`Improvement: ${((origAvg - enhAvg) / origAvg * 100).toFixed(2)}%`);
        });
        
        it('Batch verification of credentials', async() => {
            // Create a batch of credentials to verify (mix of revoked and valid)
            const batchCredentials = [];
            
            // Add 5 revoked credentials
            for (let i = 0; i < 5; i++) {
                batchCredentials.push({
                    id: credentials[i][0],
                    epoch: epochs[i]
                });
            }
            
            // Add 5 valid credentials
            for (let i = 10; i < 15; i++) {
                batchCredentials.push({
                    id: credentials[i][0],
                    epoch: epochs[i]
                });
            }
            
            // Measure time for original verification (one by one)
            const origStart = performance.now();
            const origResults = {};
            
            for (const cred of batchCredentials) {
                origResults[cred.id] = await originalSystem.verifyCredential(cred.id, cred.epoch);
            }
            
            const origEnd = performance.now();
            const origTime = origEnd - origStart;
            
            // Measure time for enhanced batch verification
            const enhStart = performance.now();
            const enhResults = await enhancedSystem.batchVerifyCredentials(batchCredentials);
            const enhEnd = performance.now();
            const enhTime = enhEnd - enhStart;
            
            console.log(`Original verification of 10 credentials: ${origTime.toFixed(2)}ms`);
            console.log(`Enhanced batch verification of 10 credentials: ${enhTime.toFixed(2)}ms`);
            console.log(`Improvement: ${((origTime - enhTime) / origTime * 100).toFixed(2)}%`);
            
            // Verify results match
            for (const cred of batchCredentials) {
                assert.equal(
                    origResults[cred.id],
                    enhResults[cred.id].valid,
                    `Batch verification results should match for credential ${cred.id}`
                );
            }
        });
    });
    
    describe("Performance Analysis", function() {
        it('Records SQL module statistics', async() => {
            // Get statistics from enhanced system
            const falsePositiveStats = enhancedSystem.getFalsePositiveStats();
            console.log("False positive stats:", falsePositiveStats);
            
            const revocationStats = enhancedSystem.getRevocationStats();
            console.log("Revocation stats:", revocationStats);
            
            // Summarize performance improvements
            console.log("\n=== PERFORMANCE SUMMARY ===");
            
            // Revocation performance
            const origRevAvg = metrics.original.revocation.reduce((a, b) => a + b, 0) / metrics.original.revocation.length;
            const enhRevAvg = metrics.enhanced.revocation.reduce((a, b) => a + b, 0) / metrics.enhanced.revocation.length;
            console.log(`\nRevocation:`);
            console.log(`  Original: ${origRevAvg.toFixed(2)}ms`);
            console.log(`  Enhanced: ${enhRevAvg.toFixed(2)}ms`);
            console.log(`  Improvement: ${((origRevAvg - enhRevAvg) / origRevAvg * 100).toFixed(2)}%`);
            
            // Valid credential verification
            const origValidVerAvg = metrics.original.verification.reduce((a, b) => a + b, 0) / metrics.original.verification.length;
            const enhValidVerAvg = metrics.enhanced.verification.reduce((a, b) => a + b, 0) / metrics.enhanced.verification.length;
            console.log(`\nVerification (valid credentials):`);
            console.log(`  Original: ${origValidVerAvg.toFixed(2)}ms`);
            console.log(`  Enhanced: ${enhValidVerAvg.toFixed(2)}ms`);
            console.log(`  Improvement: ${((origValidVerAvg - enhValidVerAvg) / origValidVerAvg * 100).toFixed(2)}%`);
        });
    });
});