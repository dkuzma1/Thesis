// sqlEnhancedSimple.test.js
var bigInt = require("big-integer");
const { performance } = require('perf_hooks');

const { web3, assert, artifacts } = require("hardhat");
const { generateCredential } = require("../utilities/credential.js");
const { gen, hashToPrime } = require("../utilities/accumulator.js");
const { initBitmap, getBitmapData, getStaticAccData, checkInclusionBitmap } = require("../utilities/bitmap.js");
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

describe("SQL-Enhanced Simple Test", function() {
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
    
    before(async function() {
        accounts = await web3.eth.getAccounts();
        holder = accounts[1];
        
        // Create issuer account with public/private keys
        issuer_ = web3.eth.accounts.create();
        issuer_Pri = issuer_.privateKey;
        issuer = issuer_.address;
        
        // Increase timeout for these tests
        this.timeout(100000);
        
        // Deploy contracts
        adminRegistryInstance = await Admin.new();
        issuerRegistryInstance = await Issuer.new(adminRegistryInstance.address);
        didRegistryInstance = await DID.new();
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
                
                // Return a structured result for integration.js
                return {
                    success: true,
                    epochId: 1, // Use fixed epoch for test
                    primeValue: credentialId // Use credential ID as prime
                };
            }
        };
        
        // Create enhanced system with SQL optimizations
        enhancedSystem = integrateWithCredentialRevocation(originalSystem);
    });
    
    it('Should issue, revoke and verify credentials correctly', async() => {
        // Generate and issue credentials
        const [currentBitmap, hashCount, count, capacity, currentEpoch] = await getBitmapData(subAccInstance);
        
        // Generate three test credentials
        for (let i = 0; i < 3; i++) {
            const [credential, credentialHash, sig] = await generateCredential(
                `test-cred-${i}`, 
                issuer, 
                accounts[4], 
                "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC", 
                currentEpoch.toNumber()
            );
            
            const [credentialPrime, nonce] = hashToPrime(credentialHash, 128, 0n);
            credentials.push({
                hash: credentialHash,
                prime: credentialPrime,
                epoch: credential.epoch
            });
        }
        
        console.log(`Created ${credentials.length} test credentials`);
        
        // Verify that all credentials are initially valid
        for (const cred of credentials) {
            const origResult = await originalSystem.verifyCredential(cred.hash, cred.epoch);
            const enhResult = await enhancedSystem.verifyCredential(cred.hash, cred.epoch);
            
            assert.isTrue(origResult, "Original system should verify credential as valid");
            assert.isTrue(enhResult.valid, "Enhanced system should verify credential as valid");
        }
        
        // Revoke the first credential
        console.log("Revoking credential 0...");
        await originalSystem.revokeCredential(credentials[0].hash, issuer);
        await enhancedSystem.revokeCredential(credentials[0].hash, issuer);
        
        // Verify revoked vs non-revoked credentials
        console.log("\nVerifying revoked credential (0):");
        const origRevokedResult = await originalSystem.verifyCredential(credentials[0].hash, credentials[0].epoch);
        const enhRevokedResult = await enhancedSystem.verifyCredential(credentials[0].hash, credentials[0].epoch);
        
        console.log(`Original verification result: ${origRevokedResult}`);
        console.log(`Enhanced verification result: ${JSON.stringify(enhRevokedResult)}`);
        
        assert.isFalse(origRevokedResult, "Original system should show credential as revoked");
        assert.isFalse(enhRevokedResult.valid, "Enhanced system should show credential as revoked");
        
        console.log("\nVerifying valid credential (1):");
        const origValidResult = await originalSystem.verifyCredential(credentials[1].hash, credentials[1].epoch);
        const enhValidResult = await enhancedSystem.verifyCredential(credentials[1].hash, credentials[1].epoch);
        
        console.log(`Original verification result: ${origValidResult}`);
        console.log(`Enhanced verification result: ${JSON.stringify(enhValidResult)}`);
        
        assert.isTrue(origValidResult, "Original system should show credential as valid");
        assert.isTrue(enhValidResult.valid, "Enhanced system should show credential as valid");
    });
    
    it('Should demonstrate SQL performance benefits', async() => {
        // Generate larger batch of credentials for performance testing
        const credentials = [];
        const [bitmap, hashCount, count, capacity, epoch] = await getBitmapData(subAccInstance);
        
        for (let i = 0; i < 10; i++) {
            const [credential, credentialHash, sig] = await generateCredential(
                `perf-cred-${i}`, 
                issuer, 
                accounts[4], 
                "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC", 
                epoch.toNumber()
            );
            
            credentials.push({
                id: credentialHash,
                epoch: credential.epoch
            });
            
            // Revoke every other credential
            if (i % 2 === 0) {
                await originalSystem.revokeCredential(credentialHash, issuer);
                await enhancedSystem.revokeCredential(credentialHash, issuer);
            }
        }
        
        // Test batch verification with enhanced system
        console.log("\nBatch verification performance:");
        
        // Original verification (no batch support)
        const origStart = performance.now();
        const origResults = {};
        
        for (const cred of credentials) {
            origResults[cred.id] = await originalSystem.verifyCredential(cred.id, cred.epoch);
        }
        
        const origEnd = performance.now();
        
        // Enhanced batch verification
        const enhStart = performance.now();
        const enhResults = await enhancedSystem.batchVerifyCredentials(credentials);
        const enhEnd = performance.now();
        
        console.log(`Original verification time: ${(origEnd - origStart).toFixed(2)}ms`);
        console.log(`Enhanced verification time: ${(enhEnd - enhStart).toFixed(2)}ms`);
        console.log(`Improvement: ${((origEnd - origStart) - (enhEnd - enhStart)).toFixed(2)}ms`);
        
        // Verify that results match
        console.log("\nVerifying result consistency:");
        let matchCount = 0;
        
        for (const cred of credentials) {
            console.log(`Credential ${cred.id.substring(0, 8)}... - Original: ${origResults[cred.id]}, Enhanced: ${enhResults[cred.id].valid}`);
            
            if (origResults[cred.id] === enhResults[cred.id].valid) {
                matchCount++;
            }
        }
        
        console.log(`${matchCount} out of ${credentials.length} results match`);
    });
});  