const hre = require("hardhat");

async function main() {
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

  // Deploy contracts
  console.log("Deploying contracts...");
  
  const did = await DID.deploy();
  await did.waitForDeployment();
  console.log("DID deployed to:", await did.getAddress());

  const credentials = await Credentials.deploy();
  await credentials.waitForDeployment();
  console.log("Credentials deployed to:", await credentials.getAddress());

  // Deploy AdminAccounts first
  console.log("Deploying AdminAccounts...");
  const adminAccounts = await AdminAccounts.deploy();
  await adminAccounts.waitForDeployment();
  console.log("AdminAccounts deployed to:", await adminAccounts.getAddress());

  // Deploy IssuerRegistry first
  console.log("Deploying IssuerRegistry...");
  const issuerRegistry = await IssuerRegistry.deploy(await adminAccounts.getAddress());
  await issuerRegistry.waitForDeployment();
  console.log("IssuerRegistry deployed to:", await issuerRegistry.getAddress());

  // Deploy SubAccumulator with IssuerRegistry address
  console.log("Deploying SubAccumulator...");
  const subAccumulator = await SubAccumulator.deploy(await issuerRegistry.getAddress());
  await subAccumulator.waitForDeployment();
  console.log("SubAccumulator deployed to:", await subAccumulator.getAddress());

  // Get addresses for other deployments
  const issuerRegistryAddress = await issuerRegistry.getAddress();
  const subAccumulatorAddress = await subAccumulator.getAddress();
  
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
  console.log("Accumulator deployed to:", await accumulator.getAddress());
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
