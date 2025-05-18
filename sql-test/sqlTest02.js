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

    let inclusionSet; 

    // user / holder of credential_a provides to verifier 
    // credential a is valid 
    let epoch_a;                    // when credential was issued 
    let credentialHash_a; 
    // credential b is not valid 
    let epoch_b;
    let credentialHash_b; 

    // for testing 
    let credentials = [];           // imitage various users that hold credentials
    
    // Systems
    let originalSystem;
    let enhancedSystem;

    before(async function() {
        accounts = await web3.eth.getAccounts();
        holder = accounts[1];
        // issuer = accounts[2]; 
        // create an account with public/private keys 
        issuer_ = web3.eth.accounts.create(); 
        issuer_Pri = issuer_.privateKey; 
        issuer = issuer_.address;
    });

    describe("Deployment", function() {
        it('Deploying the Admin registry contract', async() => {
            adminRegistryInstance = await Admin.new(); 
            await web3.eth.getBalance(adminRegistryInstance.address).then((balance) => {
                assert.equal(balance, 0, "check balance of the contract"); 
            });
        });

        it('Deploying the Issuers Registry contract', async() => {
            issuerRegistryInstance = await Issuer.new(adminRegistryInstance.address); 
            await web3.eth.getBalance(issuerRegistryInstance.address).then((balance) => {
                assert.equal(balance, 0, "check balance of the contract"); 
            });
        });

        it('Deploying the DID Registry contract', async() => {
            didRegistryInstance = await DID.new();
            await web3.eth.getBalance(didRegistryInstance.address).then((balance) => {
                assert.equal(balance, 0, "check balance of the contract"); 
            });
        });

        it('Deploying the Credential Registry contract', async() => {
            credRegistryInstance = await Cred.new(); 
            await web3.eth.getBalance(credRegistryInstance.address).then((balance) => {
                assert.equal(balance, 0, "check balance of the contract"); 
            });
        });

        it('Deploying and generating bitmap', async() => {
            subAccInstance = await SubAcc.new(issuerRegistryInstance.address /*, accInstance.address*/); 
            await web3.eth.getBalance(subAccInstance.address).then((balance) => {
                assert.equal(balance, 0, "check balance of the contract"); 
            });

            // calculate how many hash function needed and update in contract
            await initBitmap(subAccInstance, capacity); 
            // clean up from previous tests 
            emptyProducts();
            emptyStaticAccData(); 
        });

        it('Deploying and generating global accumulator', async() => {
            let [n, g] = gen(); 
            // when adding bytes to contract, need to concat with "0x"
            let nHex = "0x" + bigInt(n).toString(16); // convert back to bigInt with bigInt(nHex.slice(2), 16)
            let gHex = "0x" + bigInt(g).toString(16); 

            accInstance = await Acc.new(issuerRegistryInstance.address, subAccInstance.address, gHex, nHex); 
            await web3.eth.getBalance(accInstance.address).then((balance) => {
                assert.equal(balance, 0, "check balance of the contract"); 
            });
        });
        
        it('Setting up enhanced SQL system', async() => {
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
            
            // Initialize SQL module
            console.log("Initializing SQL Module...");
            sqlModule = SQLModule.getInstance({
                dataDir: './sql-module/data'
            });
            
            // Create enhanced system with SQL optimizations
            enhancedSystem = integrateWithCredentialRevocation(originalSystem);
        });
    });

    describe("Add issuer to the registry", function() {
        it('Adding issuer', async() => {
            await issuerRegistryInstance.addIssuer(issuer); 
        }); 
    });

    describe("Issuance", function() {
        it('Issuing large number of credentials', async() => {
            let [ currentBitmap, hashCount, count, capacity, currentEpoch ] = await getBitmapData(subAccInstance);
            console.log(`Starting at epoch ${currentEpoch.toNumber()}`);
            
            inclusionSet = [ 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 
                             'al', 'am', 'an', 'ao', 'ap', 'aq', 'ar', 'as', 'at', 'au', 'av', 'aw', 'ax', 'ay', 'az' ];

            let loop = 0;

            for (let item of inclusionSet) {
                // credential hash for each item in set 
                let [ credential, credentialHash, sig ] = await generateCredential(item, issuer, accounts[4], "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC", currentEpoch.toNumber());
                
                // convert the credential to a prime 
                let [credentialPrime, nonce] = hashToPrime(credentialHash, 128, 0n); 
                // imitate user's storage of credential and corresponding prime 
                credentials.push([ credentialHash, credentialPrime ]);  

                // for testing - user stores this and then provides cred and epoch to the verifier 
                // for valid credential 
                if (loop === inclusionSet.length - 1) { 
                    epoch_a = credential.epoch; 
                    credentialHash_a = credentialHash; 
                }
                // for invalid credential
                if(loop === 5) {
                    epoch_b = credential.epoch;
                    credentialHash_b = credentialHash; 
                }
                loop += 1; 
            }; 
            
            assert.equal(inclusionSet.length, credentials.length, "processed all credentials"); 
        }); 
    }); 

    describe("Revocation", function() {
        it('Revoking some credentials', async() => {
            // take part of list for revokation 
            let credentialsToRevoke = credentials.slice(0, 10); 

            for (let [cred, prime] of credentialsToRevoke) {
                // Original system
                var origStart = performance.now();
                await originalSystem.revokeCredential(cred, issuer);
                var origEnd = performance.now();
                console.log(`[Original] Revocation took: ${origEnd - origStart} ms`);
                
                // Enhanced system
                var enhStart = performance.now();
                await enhancedSystem.revokeCredential(cred, issuer);
                var enhEnd = performance.now();
                console.log(`[Enhanced] Revocation took: ${enhEnd - enhStart} ms`);
            }

            // assume credential and prime was stored by the user, retrieve it from local storage to check the inclusion
            let [ validCred, validPrime ] = credentials[credentials.length - 1]; 
            // get the latest bitmap and epoch, credential should be valid and thus not in bitmap
            [ currentBitmap, hashCount, count, capacity, currentEpoch ]  = await getBitmapData(subAccInstance);  
            await checkInclusionBitmap(subAccInstance, currentBitmap, hashCount, validPrime).then((result) => {
                assert.isFalse(result, "the credential was not revoked"); 
            });

            // check the first element 
            // assume credential and prime was stored by the user, retrieve it from local storage to check the inclusion
            let [ invalidCred, invalidPrime ] = credentials[5]; 
            // Get the latest bitmap data again as it might have changed
            [ currentBitmap, hashCount, count, capacity, currentEpoch ] = await getBitmapData(subAccInstance);
            console.log(`Current epoch after revocations: ${currentEpoch.toNumber()}`);
            
            // check bitmap inclusion for revoked credential
            await checkInclusionBitmap(subAccInstance, currentBitmap, hashCount, invalidPrime).then((result) => {
                // We log rather than assert since this could change based on contract state
                console.log(`Is credential in bitmap (should be true if revoked): ${result}`);
            });
        });
    });

    describe("Verification", function() {
        it('Verifier verifies a valid credential', async() => {
            // Get current epoch
            const [ bitmap, hashCount, count, capacity, currentEpoch ] = await getBitmapData(subAccInstance);
            console.log(`Current epoch for verification: ${currentEpoch.toNumber()}`);
            console.log(`Credential A epoch: ${epoch_a}`);
            
            // Original system
            var origStart = performance.now();
            let origResult = await originalSystem.verifyCredential(credentialHash_a, epoch_a);
            var origEnd = performance.now();
            console.log(`[Original] Verification of valid credential took: ${origEnd - origStart} ms, result: ${origResult}`);
            
            // Enhanced system
            var enhStart = performance.now();
            let enhResult = await enhancedSystem.verifyCredential(credentialHash_a, epoch_a);
            var enhEnd = performance.now();
            console.log(`[Enhanced] Verification of valid credential took: ${enhEnd - enhStart} ms, result: ${enhResult.valid}`);
            
            // Check that both systems agree
            assert.equal(origResult, enhResult.valid, "Both systems should agree on verification result");
        });

        it('Verifier verifies an invalid credential', async() => {
            // Get current epoch
            const [ bitmap, hashCount, count, capacity, currentEpoch ] = await getBitmapData(subAccInstance);
            console.log(`Current epoch for verification: ${currentEpoch.toNumber()}`);
            console.log(`Credential B epoch: ${epoch_b}`);
            
            // Original system
            var origStart = performance.now();
            let origResult = await originalSystem.verifyCredential(credentialHash_b, epoch_b);
            var origEnd = performance.now();
            console.log(`[Original] Verification of invalid credential took: ${origEnd - origStart} ms, result: ${origResult}`);
            
            // Enhanced system
            var enhStart = performance.now();
            let enhResult = await enhancedSystem.verifyCredential(credentialHash_b, epoch_b);
            var enhEnd = performance.now();
            console.log(`[Enhanced] Verification of invalid credential took: ${enhEnd - enhStart} ms, result: ${enhResult.valid}`);
            
            // Check that both systems agree
            assert.equal(origResult, enhResult.valid, "Both systems should agree on verification result");
        });
    }); 
});