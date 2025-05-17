const hre = require("hardhat");
// Import the SQL module
const SQLModule = require('../sql-module');
const { integrateWithCredentialRevocation } = require('../sql-module/integration');

async function main() {
  try {
    console.log("Initializing SQL Module...");
    // Initialize SQL Module with proper path to data directory
    const sqlModule = SQLModule.getInstance({
      dataDir: './sql-module/data' // Path relative to project root
    });
    
    // Log available contracts
    const artifactNames = await hre.artifacts.getAllFullyQualifiedNames();
    console.log("Available contracts:", artifactNames);
    
    // Get the contract factories with correct names from contracts list
    const DID = await hre.ethers.getContractFactory("DID");
    const Credentials = await hre.ethers.getContractFactory("Credentials");
    const Accumulator = await hre.ethers.getContractFactory("Accumulator");
    const IssuerRegistry = await hre.ethers.getContractFactory("IssuerRegistry");
    const AdminAccounts = await hre.ethers.getContractFactory("AdminAccounts");
    const SubAccumulator = await hre.ethers.getContractFactory("SubAccumulator");

    // Create a revocation batch for deployment tracking
    const batchId = sqlModule.createRevocationBatch();
    console.log("Created deployment tracking batch #", batchId);

    // Deploy contracts
    console.log("Deploying contracts...");
    
    // Deploy DID
    const did = await DID.deploy();
    await did.waitForDeployment();
    const didAddress = await did.getAddress();
    console.log("DID deployed to:", didAddress);

    // Deploy Credentials
    const credentials = await Credentials.deploy();
    await credentials.waitForDeployment();
    const credentialsAddress = await credentials.getAddress();
    console.log("Credentials deployed to:", credentialsAddress);

    // Deploy AdminAccounts
    console.log("Deploying AdminAccounts...");
    const adminAccounts = await AdminAccounts.deploy();
    await adminAccounts.waitForDeployment();
    const adminAccountsAddress = await adminAccounts.getAddress();
    console.log("AdminAccounts deployed to:", adminAccountsAddress);

    // Deploy IssuerRegistry with AdminAccounts address
    console.log("Deploying IssuerRegistry...");
    const issuerRegistry = await IssuerRegistry.deploy(adminAccountsAddress);
    await issuerRegistry.waitForDeployment();
    const issuerRegistryAddress = await issuerRegistry.getAddress();
    console.log("IssuerRegistry deployed to:", issuerRegistryAddress);

    // Deploy SubAccumulator with IssuerRegistry address
    console.log("Deploying SubAccumulator...");
    const subAccumulator = await SubAccumulator.deploy(issuerRegistryAddress);
    await subAccumulator.waitForDeployment();
    const subAccumulatorAddress = await subAccumulator.getAddress();
    console.log("SubAccumulator deployed to:", subAccumulatorAddress);

    // Initial values for g and n (you might want to adjust these)
    const g = ethers.toUtf8Bytes("1");  // Example value
    const n = ethers.toUtf8Bytes("1");  // Example value

    // Deploy Accumulator with constructor arguments
    const accumulator = await Accumulator.deploy(
      issuerRegistryAddress,
      subAccumulatorAddress,
      g,
      n
    );
    await accumulator.waitForDeployment();
    const accumulatorAddress = await accumulator.getAddress();
    console.log("Accumulator deployed to:", accumulatorAddress);
    
    // Add all deployments to the batch with meaningful data
    const deploymentRecords = [
      {
        credential_id: "contract_deploy_did",
        issuer_id: "system",
        epoch_id: 0,
        prime_value: didAddress
      },
      {
        credential_id: "contract_deploy_credentials",
        issuer_id: "system",
        epoch_id: 0,
        prime_value: credentialsAddress
      },
      {
        credential_id: "contract_deploy_admin_accounts",
        issuer_id: "system",
        epoch_id: 0,
        prime_value: adminAccountsAddress
      },
      {
        credential_id: "contract_deploy_issuer_registry",
        issuer_id: "system",
        epoch_id: 0,
        prime_value: issuerRegistryAddress
      },
      {
        credential_id: "contract_deploy_sub_accumulator",
        issuer_id: "system",
        epoch_id: 0,
        prime_value: subAccumulatorAddress
      },
      {
        credential_id: "contract_deploy_accumulator",
        issuer_id: "system",
        epoch_id: 0,
        prime_value: accumulatorAddress
      },
      {
        credential_id: "deployment_config",
        issuer_id: "system",
        epoch_id: 0,
        prime_value: JSON.stringify({
          did: didAddress,
          credentials: credentialsAddress,
          adminAccounts: adminAccountsAddress,
          issuerRegistry: issuerRegistryAddress,
          subAccumulator: subAccumulatorAddress,
          accumulator: accumulatorAddress,
          network: hre.network.name,
          timestamp: new Date().toISOString()
        })
      }
    ];
    
    // Add deployment records to batch
    sqlModule.addToBatch(batchId, deploymentRecords);
    
    // Process the batch
    const batchResult = sqlModule.processBatch(batchId);
    console.log("Deployment records processed:", batchResult);
    
    console.log("All contracts deployed and recorded in SQL module successfully!");
    
    return {
      contracts: {
        did: didAddress,
        credentials: credentialsAddress,
        adminAccounts: adminAccountsAddress,
        issuerRegistry: issuerRegistryAddress,
        subAccumulator: subAccumulatorAddress,
        accumulator: accumulatorAddress
      },
      sqlModule
    };
  } catch (error) {
    console.error("Deployment failed:", error);
    process.exitCode = 1;
  }
}

main()
  .then((deployedSystem) => {
    if (deployedSystem) {
      console.log("Deployment completed successfully.");
      // Export system for testing if needed
      global.deployedSystem = deployedSystem;
    }
  })
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });