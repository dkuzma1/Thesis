// test/sqlDebug.test.js
var bigInt = require("big-integer");

const { web3, assert, artifacts } = require("hardhat");
const { generateCredential } = require("../utilities/credential.js");
const { gen, hashToPrime } = require("../utilities/accumulator.js");
const { initBitmap, getBitmapData, checkInclusionBitmap } = require("../utilities/bitmap.js");
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

describe("SQL Integration Debug Test", function() {
    let accounts;
    let issuer;
    let issuer_Pri;
    
    // Contract instances
    let subAccInstance;
    let accInstance;
    
    // Systems
    let originalSystem;
    let enhancedSystem;
    let sqlModule;
    
    // Test credential
    let testCredential;
    let testEpoch;
    
    before(async function() {
        accounts = await web3.eth.getAccounts();
        
        // Create issuer account
        issuer_ = web3.eth.accounts.create();
        issuer_Pri = issuer_.privateKey;
        issuer = issuer_.address;
        
        // Deploy contracts
        const adminRegistryInstance = await Admin.new();
        const issuerRegistryInstance = await Issuer.new(adminRegistryInstance.address);
        await DID.new();
        await Cred.new();
        subAccInstance = await SubAcc.new(issuerRegistryInstance.address);
        
        // Initialize bitmap
        await initBitmap(subAccInstance, 30);
        
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
                console.log(`Original system verifying credential ${credentialId.substr(0, 8)}... at epoch ${epochId}`);
                const result = await verify(credentialId, epochId, subAccInstance, accInstance);
                console.log(`Original verification result: ${result}`);
                return result;
            },
            
            revokeCredential: async (credentialId, issuerId) => {
                console.log(`Original system revoking credential ${credentialId.substr(0, 8)}...`);
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
        
        // Generate a test credential
        const [bitmap, hashCount, count, capacity, epoch] = await getBitmapData(subAccInstance);
        const [credential, credentialHash, sig] = await generateCredential(
            "debug-test-cred", 
            issuer, 
            accounts[4], 
            "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC", 
            epoch.toNumber()
        );
        
        testCredential = credentialHash;
        testEpoch = credential.epoch;
        
        console.log(`Created test credential ${testCredential.substr(0, 8)}... at epoch ${testEpoch}`);
    });
    
    it('Debug verification discrepancy', async function() {
        // First verify without revocation (should be valid)
        console.log("\n=== Verifying before revocation ===");
        
        const origValidResult = await originalSystem.verifyCredential(testCredential, testEpoch);
        console.log(`Original result: ${origValidResult}`);
        
        const enhValidResult = await enhancedSystem.verifyCredential(testCredential, testEpoch);
        console.log(`Enhanced result: ${JSON.stringify(enhValidResult)}`);
        
        assert.isTrue(origValidResult, "Original system should confirm credential is valid");
        assert.isTrue(enhValidResult.valid, "Enhanced system should confirm credential is valid");
        
        // Now revoke the credential
        console.log("\n=== Revoking credential ===");
        
        // Check Bloom filter directly
        const [bitmap, hashCount, count, capacity, epoch] = await getBitmapData(subAccInstance);
        const [credentialPrime, nonce] = hashToPrime(testCredential, 128, 0n);
        
        console.log(`Before revocation, Bloom filter check: ${await checkInclusionBitmap(subAccInstance, bitmap, hashCount, credentialPrime)}`);
        
        // Revoke in both systems
        await originalSystem.revokeCredential(testCredential, issuer);
        await enhancedSystem.revokeCredential(testCredential, issuer);
        
        // Check Bloom filter again
        const [bitmap2, hashCount2, count2, capacity2, epoch2] = await getBitmapData(subAccInstance);
        console.log(`After revocation, Bloom filter check: ${await checkInclusionBitmap(subAccInstance, bitmap2, hashCount2, credentialPrime)}`);
        
        // Verify again after revocation
        console.log("\n=== Verifying after revocation ===");
        
        const origRevokedResult = await originalSystem.verifyCredential(testCredential, testEpoch);
        console.log(`Original result: ${origRevokedResult}`);
        
        const enhRevokedResult = await enhancedSystem.verifyCredential(testCredential, testEpoch);
        console.log(`Enhanced result: ${JSON.stringify(enhRevokedResult)}`);
        
        // Check SQL database directly
        console.log("\n=== Checking SQL database ===");
        const sqlStats = enhancedSystem.getRevocationStats();
        console.log(`Revocation stats: ${JSON.stringify(sqlStats)}`);
        
        assert.isFalse(origRevokedResult, "Original system should detect credential as revoked");
        assert.isFalse(enhRevokedResult.valid, "Enhanced system should detect credential as revoked");
    });
});