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


describe("SQL-Enhanced Evaluation Test", function() {
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

    // let inclusionSet; 

    // for testing 
    let credentials = []            // imitate various users that hold credentials   
    let epochs = []

    // Systems
    let originalSystem;
    let enhancedSystem;

    // Performance metrics
    const metrics = {
        original: {
            verification: {
                valid: [],
                revoked: []
            },
            revocation: []
        },
        enhanced: {
            verification: {
                valid: [],
                revoked: []
            },
            revocation: []
        }
    };

    before(async function() {
        accounts = await web3.eth.getAccounts();
        holder = accounts[1];
        
        // create an account with public/private keys 
        issuer_ = web3.eth.accounts.create(); 
        issuer_Pri = issuer_.privateKey; 
        issuer = issuer_.address;
    });

    describe("Deployment", function() {
        it('Deploying the contracts and initializing systems', async() => {
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
            
            // Create enhanced system with SQL optimizations
            enhancedSystem = integrateWithCredentialRevocation(originalSystem);
        });
    });

    describe("Performance Testing", function() {
        function makeid(length) {
            var result = '';
            var characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
            var charactersLength = characters.length;
            for (var i = 0; i < length; i++) {
                result += characters.charAt(Math.floor(Math.random() * charactersLength));
            }
            return result;
        }

        it('Should issue test credentials', async function() {
            const testCredentials = 50; // Number of credentials to test
            
            console.log(`\nGenerating ${testCredentials} test credentials...`);
            const [bitmap, hashCount, count, capacity, epoch] = await getBitmapData(subAccInstance);
            
            for (let i = 0; i < testCredentials; i++) {
                // Generate a random claim
                let claim = makeid(5);
                
                // Generate a credential
                const [credential, credentialHash, sig] = await generateCredential(
                    claim, 
                    issuer, 
                    holder, 
                    "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC", 
                    epoch.toNumber()
                );
                
                // Store credential info
                credentials.push({
                    id: credentialHash,
                    epoch: credential.epoch
                });
                
                epochs.push(credential.epoch);
            }
            
            assert.equal(credentials.length, testCredentials, `Should have generated ${testCredentials} credentials`);
        });
        
        it('Should revoke a portion of the credentials and measure performance', async function() {
            const revocationCount = Math.floor(credentials.length * 0.3);
            console.log(`\nRevoking ${revocationCount} credentials...`);
            
            for (let i = 0; i < revocationCount; i++) {
                // Measure original revocation performance
                const origStart = performance.now();
                await originalSystem.revokeCredential(credentials[i].id, issuer);
                const origEnd = performance.now();
                metrics.original.revocation.push(origEnd - origStart);
                
                // Measure enhanced revocation performance
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
        
        it('Should verify both revoked and valid credentials and measure performance', async function() {
            // Get revoked and valid credential counts
            const revokedCount = metrics.original.revocation.length;
            const validCount = credentials.length - revokedCount;
            
            console.log(`\nVerifying ${revokedCount} revoked credentials...`);
            
            // Verify revoked credentials
            for (let i = 0; i < revokedCount; i++) {
                const cred = credentials[i];
                
                // Measure original verification
                const origStart = performance.now();
                const origResult = await originalSystem.verifyCredential(cred.id, cred.epoch);
                const origEnd = performance.now();
                metrics.original.verification.revoked.push(origEnd - origStart);
                
                // Measure enhanced verification
                const enhStart = performance.now();
                const enhResult = await enhancedSystem.verifyCredential(cred.id, cred.epoch);
                const enhEnd = performance.now();
                metrics.enhanced.verification.revoked.push(enhEnd - enhStart);
                
                // Check if results match
                assert.equal(!origResult, !enhResult.valid, `Verification results should match for revoked credential ${i}`);
            }
            
            console.log(`\nVerifying ${validCount} valid credentials...`);
            
            // Verify valid credentials (test a subset equal to revoked count for balance)
            const validTestCount = Math.min(revokedCount, validCount);
            for (let i = 0; i < validTestCount; i++) {
                const index = revokedCount + i; // Start after revoked credentials
                const cred = credentials[index];
                
                // Measure original verification
                const origStart = performance.now();
                const origResult = await originalSystem.verifyCredential(cred.id, cred.epoch);
                const origEnd = performance.now();
                metrics.original.verification.valid.push(origEnd - origStart);
                
                // Measure enhanced verification
                const enhStart = performance.now();
                const enhResult = await enhancedSystem.verifyCredential(cred.id, cred.epoch);
                const enhEnd = performance.now();
                metrics.enhanced.verification.valid.push(enhEnd - enhStart);
                
                // Check if results match
                assert.equal(origResult, enhResult.valid, `Verification results should match for valid credential ${index}`);
            }
            
            // Calculate and log performance metrics for revoked credentials
            const origRevokedAvg = metrics.original.verification.revoked.reduce((a, b) => a + b, 0) / 
                                metrics.original.verification.revoked.length;
                                
            const enhRevokedAvg = metrics.enhanced.verification.revoked.reduce((a, b) => a + b, 0) / 
                               metrics.enhanced.verification.revoked.length;
            
            console.log(`\nRevoked credential verification performance:`);
            console.log(`Original system average: ${origRevokedAvg.toFixed(2)}ms`);
            console.log(`Enhanced system average: ${enhRevokedAvg.toFixed(2)}ms`);
            console.log(`Difference: ${(enhRevokedAvg - origRevokedAvg).toFixed(2)}ms (${((enhRevokedAvg - origRevokedAvg) / origRevokedAvg * 100).toFixed(2)}%)`);
            
            // Calculate and log performance metrics for valid credentials
            const origValidAvg = metrics.original.verification.valid.reduce((a, b) => a + b, 0) / 
                               metrics.original.verification.valid.length;
                               
            const enhValidAvg = metrics.enhanced.verification.valid.reduce((a, b) => a + b, 0) / 
                              metrics.enhanced.verification.valid.length;
            
            console.log(`\nValid credential verification performance:`);
            console.log(`Original system average: ${origValidAvg.toFixed(2)}ms`);
            console.log(`Enhanced system average: ${enhValidAvg.toFixed(2)}ms`);
            console.log(`Difference: ${(enhValidAvg - origValidAvg).toFixed(2)}ms (${((enhValidAvg - origValidAvg) / origValidAvg * 100).toFixed(2)}%)`);
        });

        it('Should test repeated verification to measure caching benefit', async function() {
            console.log("\nTesting repeated verification performance (caching benefit)...");
            
            // Select 5 credentials to repeatedly verify
            const testCredentials = [
                ...credentials.slice(0, 2),  // Revoked
                ...credentials.slice(metrics.original.revocation.length, metrics.original.revocation.length + 3)  // Valid
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