var bigInt = require("big-integer");

const { web3, assert, artifacts } = require("hardhat");
const { generateCredential } = require("../utilities/credential.js"); 
const { gen, hashToPrime } = require("../utilities/accumulator.js"); 
const { initBitmap, getBitmapData, getStaticAccData, checkInclusionBitmap } = require("../utilities/bitmap.js"); 

const { emptyProducts, emptyStaticAccData } = require("../utilities/product"); 
const { revoke, verify } = require("../revocation/revocation"); 

// Import SQL module
const SQLModule = require("../sql-module");
const { integrateWithCredentialRevocation } = require("../sql-module/integration");

// using the following approach for testing: 
// https://hardhat.org/hardhat-runner/docs/other-guides/truffle-testing

const DID = artifacts.require("DID"); 
const Cred = artifacts.require("Credentials"); 
const Admin = artifacts.require("AdminAccounts"); 
const Issuer = artifacts.require("IssuerRegistry"); 
const SubAcc = artifacts.require("SubAccumulator"); 
const Acc = artifacts.require("Accumulator"); 


describe("SQL-Enhanced Testing revocation across different epoch", function() {
    let accounts;
    let holder;
    let issuer; 

    let issuer_; 
    let issuer_Pri;

    // bitmap capacity 
    let capacity = 20; // up to uin256 max elements 

    // contract instances 
    let adminRegistryInstance; 
    let issuerRegistryInstance; 
    let didRegistryInstance; 
    let credRegistryInstance; 
    let subAccInstance; 
    let accInstance; 

    // for testing 
    let credentials = []            // imitate various users that hold credentials   
    let epochs = []

    let totalCreds = 0; 

    // Systems
    let originalSystem;
    let enhancedSystem;

    before(async function() {
        accounts = await web3.eth.getAccounts();
        holder = accounts[1];
        
        // create an account with public/private keys 
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
            
            // Deploy global accumulator
            let [n, g] = gen(); 
            let nHex = "0x" + bigInt(n).toString(16);
            let gHex = "0x" + bigInt(g).toString(16); 
            
            accInstance = await Acc.new(issuerRegistryInstance.address, subAccInstance.address, gHex, nHex); 
            
            // Add issuer to registry
            await issuerRegistryInstance.addIssuer(issuer);
            
            // Create original system
            originalSystem = {
                verifyCredential: async (credentialId, epochId) => {
                    return await verify(credentialId, epochId, subAccInstance, accInstance);
                },
                
                revokeCredential: async (credentialId, issuerId) => {
                    await revoke(credentialId, subAccInstance, accInstance, issuer_Pri);
                    
                    return {
                        success: true,
                        epochId: 1
                    };
                }
            };
            
            // Initialize SQL module
            console.log("Initializing SQL Module...");
            sqlModule = SQLModule.getInstance({
                dataDir: './sql-module/data'
            });
            
            // Create enhanced system with SQL optimizations
            enhancedSystem = integrateWithCredentialRevocation(originalSystem);
        });
    });

    describe("Issuance & verification", function() {
        function makeid(length) {
            var result = '';
            var characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
            var charactersLength = characters.length;
            for (var i = 0; i < length; i++) {
                result += characters.charAt(Math.floor(Math.random() * charactersLength));
            }
            return result;
        }

        async function issueCreds() {
            for (let i = 0; i < 20; i++) {
                let item = makeid(5);
                let [ currentBitmap, hashCount, count, capacity, currentEpoch ] = await getBitmapData(subAccInstance);
                // credential hash for each item in set 
                let [ credential, credentialHash, sig ] = await generateCredential(item, issuer, accounts[4], "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC", currentEpoch.toNumber());
                // convert the credential to a prime 
                let [credentialPrime, nonce] = hashToPrime(credentialHash, 128, 0n); 
                // imitate user's storage of credential and corresponding prime 
                credentials.push([ credentialHash, credentialPrime ]); 
                epochs.push(credential.epoch);
                totalCreds += 1; 
            }; 
        }

        async function revokeCreds(start, end) {
            // Test both original and enhanced systems for revocation
            for (let i = start; i < end; i++) {
                let [ currentBitmap, hashCount, count, capacity, currentEpoch ] = await getBitmapData(subAccInstance);
                
                // Original system
                var origStart = performance.now();
                await originalSystem.revokeCredential(credentials[i][0], issuer);
                var origEnd = performance.now(); 
                console.log(`[Original] Total # of credes: ${totalCreds} | revocation epoch: ${currentEpoch.toNumber()} | took: ${origEnd - origStart} ms`);
                
                // Enhanced system
                var enhStart = performance.now();
                await enhancedSystem.revokeCredential(credentials[i][0], issuer);
                var enhEnd = performance.now();
                console.log(`[Enhanced] Total # of credes: ${totalCreds} | revocation epoch: ${currentEpoch.toNumber()} | took: ${enhEnd - enhStart} ms`);
            }
        }

        async function verifyCred(num) {
            let [ currentBitmap, hashCount, count, capacity, currentEpoch ] = await getBitmapData(subAccInstance);
            
            // Original system
            var origStart = performance.now();
            let origVerification = await originalSystem.verifyCredential(credentials[num][0], epochs[num]); 
            var origEnd = performance.now();
            console.log(`[Original] ${origVerification}: Verify credential issued at current: ${currentEpoch.toNumber()} | issued at: ${epochs[num]} | took: ${origEnd - origStart} ms`);
            
            // Enhanced system
            var enhStart = performance.now();
            let enhVerification = await enhancedSystem.verifyCredential(credentials[num][0], epochs[num]);
            var enhEnd = performance.now();
            console.log(`[Enhanced] ${enhVerification.valid}: Verify credential issued at current: ${currentEpoch.toNumber()} | issued at: ${epochs[num]} | took: ${enhEnd - enhStart} ms`);
            
            // Verify results match
            assert.equal(origVerification, enhVerification.valid, "Verification results should match");
        }

        it('Issuing credentials, round 1', async() => {
            await issueCreds(); 
        }); 

        it('Issuing credentials, round 2', async() => {
            await issueCreds(); 
        });

        it('Issuing credentials, round 3', async() => {
            await issueCreds(); 
        });

        it('Revoke credentials, round 1', async() => {
            await revokeCreds(0, 10); 
        });

        it('Revoke credentials, round 2', async() => {
            await revokeCreds(10, 20); 
        }); 

        it('Verify credentials - recently issued', async() => {
            // Verify a credential from the most recent batch
            await verifyCred(totalCreds - 5); 
        });

        it('Verify credentials - recently revoked', async() => {
            // Verify a credential from the revoked batch
            await verifyCred(15); 
        });

        it('Verify credentials - earlier epoch', async() => {
            // Verify a credential from the first batch
            await verifyCred(5); 
        });

        it('Testing caching benefits - first verification', async() => {
            // Pick a credential for repeated verification
            const testCredential = 25; // From middle batch
            console.log(`\nTesting verification with caching benefits (credential #${testCredential}):`);
            
            // First verification pass
            console.log("First verification pass:");
            
            // Original system
            var origStart1 = performance.now();
            let origResult1 = await originalSystem.verifyCredential(credentials[testCredential][0], epochs[testCredential]);
            var origEnd1 = performance.now();
            console.log(`[Original] First verification: ${origEnd1 - origStart1} ms`);
            
            // Enhanced system
            var enhStart1 = performance.now();
            let enhResult1 = await enhancedSystem.verifyCredential(credentials[testCredential][0], epochs[testCredential]);
            var enhEnd1 = performance.now();
            console.log(`[Enhanced] First verification: ${enhEnd1 - enhStart1} ms`);
        });

        it('Testing caching benefits - second verification', async() => {
            // Second verification of the same credential
            const testCredential = 25; // Same credential as previous test
            console.log("Second verification pass (repeated):");
            
            // Original system
            var origStart2 = performance.now();
            let origResult2 = await originalSystem.verifyCredential(credentials[testCredential][0], epochs[testCredential]);
            var origEnd2 = performance.now();
            console.log(`[Original] Second verification: ${origEnd2 - origStart2} ms`);
            
            // Enhanced system
            var enhStart2 = performance.now();
            let enhResult2 = await enhancedSystem.verifyCredential(credentials[testCredential][0], epochs[testCredential]);
            var enhEnd2 = performance.now();
            console.log(`[Enhanced] Second verification: ${enhEnd2 - enhStart2} ms`);
        });

        it('Verify with batch operations', async() => {
            console.log(`\nTesting batch verification:`);
            
            // Select a batch of credentials to verify
            const credBatch = [
                {id: credentials[5][0], epoch: epochs[5]},   // From early batch
                {id: credentials[25][0], epoch: epochs[25]}, // From middle batch
                {id: credentials[50][0], epoch: epochs[50]}  // From recent batch
            ];
            
            // Original system (one by one)
            var origStart = performance.now();
            const origResults = {};
            
            for (const cred of credBatch) {
                origResults[cred.id] = await originalSystem.verifyCredential(cred.id, cred.epoch);
            }
            
            var origEnd = performance.now();
            
            // Enhanced system (batch)
            var enhStart = performance.now();
            const enhResults = await enhancedSystem.batchVerifyCredentials(credBatch);
            var enhEnd = performance.now();
            
            console.log(`[Original] Batch verification (one by one): ${origEnd - origStart} ms (${(origEnd - origStart) / credBatch.length} ms per credential)`);
            console.log(`[Enhanced] Batch verification: ${enhEnd - enhStart} ms (${(enhEnd - enhStart) / credBatch.length} ms per credential)`);
            
            // Check that results match
            let matchCount = 0;
            for (const cred of credBatch) {
                if (origResults[cred.id] === enhResults[cred.id].valid) {
                    matchCount++;
                }
            }
            
            console.log(`Results match: ${matchCount}/${credBatch.length}`);
            assert.equal(matchCount, credBatch.length, "All verification results should match");
        });
    }); 

    after(function() {
        // Display performance summary from SQL module
        console.log("\n=== PERFORMANCE SUMMARY ===");
        
        // Get SQL module stats
        console.log("\nSQL Module Statistics:");
        console.log(enhancedSystem.getRevocationStats());
        
        console.log("\nFalse Positive Statistics:");
        console.log(enhancedSystem.getFalsePositiveStats());
    });
});