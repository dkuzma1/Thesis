var bigInt = require("big-integer");

const { web3, assert, artifacts } = require("hardhat");
const { generateCredential } = require("../utilities/credential.js"); 
const { gen, add, genMemWit, genNonMemWit, verMem, verNonMem, generatePrimes, hashToPrime } = require("../utilities/accumulator.js"); 
const { initBitmap, addToBitmap, getBitmapData, getStaticAccData, checkInclusionBitmap } = require("../utilities/bitmap.js"); 

const { storeStaticAccData, readStaticAccProducts, updateProducts } = require("../utilities/product.js");
const { emptyProducts, emptyStaticAccData } = require("../utilities/product"); 
const { revoke, verify } = require("../revocation/revocation"); 

// Import SQL module
const SQLModule = require("../sql-module");
const { integrateWithCredentialRevocation } = require("../sql-module/integration");

const { performance } = require('perf_hooks');

// using the following approach for testing: 
// https://hardhat.org/hardhat-runner/docs/other-guides/truffle-testing

const DID = artifacts.require("DID"); 
const Cred = artifacts.require("Credentials"); 
const Admin = artifacts.require("AdminAccounts"); 
const Issuer = artifacts.require("IssuerRegistry"); 
const SubAcc = artifacts.require("SubAccumulator"); 
const Acc = artifacts.require("Accumulator"); 


describe("SQL-Enhanced Cryptographic Operations Testing", function() {
    let accounts;
    let holder;
    let issuer; 

    let issuer_; 
    let issuer_Pri;

    let n; 
    let g; 

    // bitmap capacity 
    let capacity = 20; 

    // contract instances 
    let adminRegistryInstance; 
    let issuerRegistryInstance; 
    let didRegistryInstance; 
    let credRegistryInstance; 
    let subAccInstance; 
    let accInstance; 

    // Storage for testing
    let data = [];        // Revoked primes
    let products = [];    // Products for witness updates
    let credentials = []; // Test credentials
    
    // Systems
    let originalSystem;
    let enhancedSystem;
    let sqlModule;

    before(async function() {
        accounts = await web3.eth.getAccounts();
        holder = accounts[1];
        
        issuer_ = web3.eth.accounts.create(); 
        issuer_Pri = issuer_.privateKey; 
        issuer = issuer_.address;
    });

    describe("Deployment", function() {
        it('Deploying all contracts and initializing systems', async() => {
            // Deploy contracts
            adminRegistryInstance = await Admin.new(); 
            issuerRegistryInstance = await Issuer.new(adminRegistryInstance.address); 
            didRegistryInstance = await DID.new();
            credRegistryInstance = await Cred.new(); 
            subAccInstance = await SubAcc.new(issuerRegistryInstance.address); 
            
            // Initialize bitmap
            await initBitmap(subAccInstance, capacity); 
            emptyProducts();
            emptyStaticAccData(); 
            
            // Generate RSA parameters for accumulator
            [n, g] = gen(); 
            
            // Deploy accumulator
            let nHex = "0x" + bigInt(n).toString(16);
            let gHex = "0x" + bigInt(g).toString(16); 
            
            accInstance = await Acc.new(issuerRegistryInstance.address, subAccInstance.address, gHex, nHex); 
            
            // Add issuer to registry
            await issuerRegistryInstance.addIssuer(issuer);
            
            // Initialize SQL module
            console.log("Initializing SQL Module...");
            sqlModule = SQLModule.getInstance({
                dataDir: './sql-module/data'
            });
            
            // Create original system
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
    });

    describe("Cryptographic Operations", function() {
        function makeid(length) {
            var result = '';
            var characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
            var charactersLength = characters.length;
            for (var i = 0; i < length; i++) {
                result += characters.charAt(Math.floor(Math.random() * charactersLength));
            }
            return result;
        }
        
        function update_product(x, data) {
            let product_base = 1; 
            for (let i = 0; i < data.length - 1; i++) {
                product_base = bigInt(product_base).multiply(data[i]);
                if (products[i]) {
                    products[i] = bigInt(products[i]).multiply(x);
                } else {
                    products.push(bigInt(product_base));
                }
            }
            products.push(bigInt(product_base));
        }

        async function generateTestCredentials(count) {
            console.log(`Generating ${count} test credentials...`);
            
            const newCredentials = [];
            
            for (let i = 0; i < count; i++) {
                let item = makeid(5);
                let [ currentBitmap, hashCount, _count, _capacity, currentEpoch ] = await getBitmapData(subAccInstance);
                
                // Generate credential
                let [ credential, credentialHash, sig ] = await generateCredential(
                    item, issuer, accounts[4], "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC", currentEpoch.toNumber()
                );
                
                // Convert to prime
                let [credentialPrime, nonce] = hashToPrime(credentialHash, 128, 0n); 
                
                // Store credential data
                newCredentials.push([credentialHash, credentialPrime]);
                
                // Log progress periodically
                if ((i+1) % 20 === 0 || i === count-1) {
                    console.log(`Generated ${i+1}/${count} credentials`);
                }
            }
            
            credentials.push(...newCredentials);
            return newCredentials;
        }

        it('Testing cryptographic operations - Round 1', async() => {
            // Generate test credentials
            const testCreds = await generateTestCredentials(5);
            
            console.log("Testing direct cryptographic operations - Round 1");
            
            // Process credentials one by one
            for (let i = 0; i < testCreds.length; i++) {
                const [credHash, credPrime] = testCreds[i];
                
                console.log(`\nProcessing credential ${i+1}/${testCreds.length}`);
                
                // Test direct accumulator update
                console.log(`Testing direct accumulator update...`);
                const directStart = performance.now();
                
                // Updated acc with revoked credential 
                let acc = add(g, n, credPrime); 
                
                // Store revoked prime 
                data.push(credPrime); 
                
                // Update products with new prime 
                update_product(credPrime, data);
                
                const directEnd = performance.now();
                console.log(`Direct cryptographic update took: ${(directEnd - directStart).toFixed(2)}ms`);
                
                // Test blockchain revocation
                console.log(`Testing blockchain revocation...`);
                const blockchainStart = performance.now();
                await originalSystem.revokeCredential(credHash, issuer);
                const blockchainEnd = performance.now();
                console.log(`Blockchain revocation took: ${(blockchainEnd - blockchainStart).toFixed(2)}ms`);
                
                // Test SQL-enhanced revocation
                console.log(`Testing SQL-enhanced revocation...`);
                const sqlStart = performance.now();
                await enhancedSystem.revokeCredential(credHash, issuer);
                const sqlEnd = performance.now();
                console.log(`SQL-enhanced revocation took: ${(sqlEnd - sqlStart).toFixed(2)}ms`);
            }
        });

        it('Testing witness generation and updates', async() => {
            console.log("\nTesting witness generation and updates");
            
            // Generate more credentials for testing
            const witnessTestCreds = await generateTestCredentials(5);
            
            // Calculate base accumulator for the existing revoked credentials
            let acc = g;
            for (const prime of data) {
                acc = add(acc, n, prime);
            }
            
            console.log(`\nAccumulator value after ${data.length} revocations: ${acc}`);
            
            // Test witness generation
            console.log("\nTesting witness generation for non-revoked credential...");
            const [testHash, testPrime] = witnessTestCreds[0];
            
            const witGenStart = performance.now();
            const witness = bigInt(g).modPow(products[0], n);
            const witGenEnd = performance.now();
            
            console.log(`Witness generation took: ${(witGenEnd - witGenStart).toFixed(2)}ms`);
            
            // Test witness verification
            console.log("\nTesting witness verification...");
            const verifyStart = performance.now();
            const isValid = verMem(acc, n, testPrime, witness);
            const verifyEnd = performance.now();
            
            console.log(`Witness verification result: ${isValid}`);
            console.log(`Witness verification took: ${(verifyEnd - verifyStart).toFixed(2)}ms`);
            
            // Revoke another credential
            console.log("\nRevoking another credential and updating witness...");
            const [newHash, newPrime] = witnessTestCreds[1];
            
            // Update accumulator
            const updAccStart = performance.now();
            acc = add(acc, n, newPrime);
            data.push(newPrime);
            update_product(newPrime, data);
            const updAccEnd = performance.now();
            
            console.log(`Accumulator update took: ${(updAccEnd - updAccStart).toFixed(2)}ms`);
            
            // Update witness
            const updWitStart = performance.now();
            const updatedWitness = bigInt(g).modPow(products[products.length-2], n);
            const updWitEnd = performance.now();
            
            console.log(`Witness update took: ${(updWitEnd - updWitStart).toFixed(2)}ms`);
            
            // Verify updated witness
            const updVerStart = performance.now();
            const updIsValid = verMem(acc, n, testPrime, updatedWitness);
            const updVerEnd = performance.now();
            
            console.log(`Updated witness verification result: ${updIsValid}`);
            console.log(`Updated witness verification took: ${(updVerEnd - updVerStart).toFixed(2)}ms`);
        });

        it('Comparing verification methods', async() => {
            console.log("\nComparing different verification methods");
            
            // Generate a new credential for testing
            const [verCredHash, verCredPrime] = (await generateTestCredentials(1))[0];
            
            // Get current epoch
            let [ currentBitmap, hashCount, _count, _capacity, currentEpoch ] = await getBitmapData(subAccInstance);
            
            // Test direct cryptographic verification
            console.log("\nTesting direct cryptographic verification...");
            const cryptoStart = performance.now();
            
            // Check if credential is in accumulator
            let acc = g;
            for (const prime of data) {
                acc = add(acc, n, prime);
            }
            
            const witness = bigInt(g).modPow(products[products.length-1], n);
            const cryptoResult = verMem(acc, n, verCredPrime, witness);
            
            const cryptoEnd = performance.now();
            
            console.log(`Direct crypto verification result: ${cryptoResult}`);
            console.log(`Direct crypto verification took: ${(cryptoEnd - cryptoStart).toFixed(2)}ms`);
            
            // FIX: First ensure epoch data has been stored properly
            // This ensures that the required epoch data exists in the accumulator
            console.log("\nPreparing blockchain verification...");
            
            // First ensure we add some data to the current epoch for the accumulator to track
            // This avoids the "Cannot read properties of null (reading 'slice')" error
            const prepStartTime = performance.now();
            
            try {
                // Create dummy credential to ensure epoch data is stored
                let dummyItem = makeid(5);
                let [ credential, credentialHash, sig ] = await generateCredential(
                    dummyItem, issuer, accounts[4], "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC", currentEpoch.toNumber()
                );
                
                // Convert to prime and revoke (this stores epoch data)
                let [credentialPrime, nonce] = hashToPrime(credentialHash, 128, 0n);
                await originalSystem.revokeCredential(credentialHash, issuer);
                data.push(credentialPrime);
                update_product(credentialPrime, data);
                
                // Store the static acc data for current epoch
                await addToBitmap(subAccInstance, accInstance, credentialPrime, issuer_Pri);
                
                const prepEndTime = performance.now();
                console.log(`Preparation took: ${(prepEndTime - prepStartTime).toFixed(2)}ms`);
            } catch (error) {
                console.error("Preparation error:", error.message);
            }
            
            // Test blockchain verification
            console.log("\nTesting blockchain verification...");
            const blockchainStart = performance.now();
            let blockchainResult;
            
            try {
                blockchainResult = await verify(verCredHash, currentEpoch.toNumber(), subAccInstance, accInstance);
                console.log(`Blockchain verification result: ${blockchainResult}`);
            } catch (error) {
                console.error("Blockchain verification error:", error.message);
                blockchainResult = null;
            }
            
            const blockchainEnd = performance.now();
            console.log(`Blockchain verification took: ${(blockchainEnd - blockchainStart).toFixed(2)}ms`);
            
            // Test SQL-enhanced verification
            console.log("\nTesting SQL-enhanced verification...");
            const sqlStart = performance.now();
            let sqlResult;
            
            try {
                sqlResult = await enhancedSystem.verifyCredential(verCredHash, currentEpoch.toNumber());
                console.log(`SQL verification result: ${sqlResult ? sqlResult.valid : 'error'}, method: ${sqlResult ? sqlResult.method : 'unknown'}`);
            } catch (error) {
                console.error("SQL verification error:", error.message);
                sqlResult = null;
            }
            
            const sqlEnd = performance.now();
            console.log(`SQL verification took: ${(sqlEnd - sqlStart).toFixed(2)}ms`);
        });

        it('Testing batch operations with signatures', async() => {
            console.log("\nTesting batch operations with signatures");
            
            // Generate several new credentials
            const batchCreds = await generateTestCredentials(10);
            
            // Test batch revocation with blockchain approach
            console.log("\nTesting batch revocation with blockchain...");
            const blockchainBatchStart = performance.now();
            
            for (const [credHash, credPrime] of batchCreds) {
                await originalSystem.revokeCredential(credHash, issuer);
            }
            
            const blockchainBatchEnd = performance.now();
            const blockchainAvg = (blockchainBatchEnd - blockchainBatchStart) / batchCreds.length;
            
            console.log(`Blockchain batch revocation took: ${(blockchainBatchEnd - blockchainBatchStart).toFixed(2)}ms (${blockchainAvg.toFixed(2)}ms per credential)`);
            
            // Test direct cryptographic batch operations
            console.log("\nTesting direct cryptographic batch operations...");
            const cryptoBatchStart = performance.now();
            
            let batchAcc = g;
            for (const [_credHash, credPrime] of batchCreds) {
                batchAcc = add(batchAcc, n, credPrime);
                data.push(credPrime);
                update_product(credPrime, data);
            }
            
            const cryptoBatchEnd = performance.now();
            const cryptoAvg = (cryptoBatchEnd - cryptoBatchStart) / batchCreds.length;
            
            console.log(`Direct crypto batch operations took: ${(cryptoBatchEnd - cryptoBatchStart).toFixed(2)}ms (${cryptoAvg.toFixed(2)}ms per credential)`);
            
            // Test SQL-enhanced batch operations (direct individual revocations)
            console.log("\nTesting SQL-enhanced individual revocations...");
            const sqlBatchStart = performance.now();
            
            for (const [credHash, _credPrime] of batchCreds) {
                await enhancedSystem.revokeCredential(credHash, issuer);
            }
            
            const sqlBatchEnd = performance.now();
            const sqlAvg = (sqlBatchEnd - sqlBatchStart) / batchCreds.length;
            
            console.log(`SQL-enhanced individual revocations took: ${(sqlBatchEnd - sqlBatchStart).toFixed(2)}ms (${sqlAvg.toFixed(2)}ms per credential)`);
        });
    });

    after(function() {
        // Display performance summary
        console.log("\n=== PERFORMANCE SUMMARY ===");
        
        // Get SQL module stats
        try {
            console.log("\nRevocation Statistics:");
            const revStats = enhancedSystem.getRevocationStats();
            console.log(`Total revocations: ${revStats.totalRevocations}`);
            
            console.log("\nPerformance Metrics:");
            revStats.performanceMetrics.forEach(metric => {
                console.log(`${metric.operation_type}: avg=${metric.avg_execution_time.toFixed(2)}ms, min=${metric.min_execution_time.toFixed(2)}ms, max=${metric.max_execution_time.toFixed(2)}ms, count=${metric.operation_count}`);
            });
            
            console.log("\nFalse Positive Statistics:");
            const fpStats = enhancedSystem.getFalsePositiveStats();
            fpStats.forEach(stat => {
                console.log(`Epoch ${stat.epoch_id}: ${stat.total_false_positives} false positives, avg occurrences: ${stat.avg_occurrences.toFixed(2)}, max: ${stat.max_occurrences}`);
            });
        } catch (error) {
            console.error("Error getting statistics:", error.message);
        }
    });
});