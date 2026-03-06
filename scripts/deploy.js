/**
 * Hardhat deployment script for VotingLedger.sol
 * ================================================
 * Usage
 * -----
 *   # Install Hardhat (once):
 *   npm install --save-dev hardhat @nomicfoundation/hardhat-toolbox
 *
 *   # Local Hardhat node:
 *   npx hardhat node                                     # terminal 1
 *   npx hardhat run scripts/deploy.js --network localhost  # terminal 2
 *
 *   # Sepolia testnet (requires ETH_PRIVATE_KEY + INFURA_API_KEY in .env):
 *   npx hardhat run scripts/deploy.js --network sepolia
 *
 * Environment variables (place in a .env file at the repo root)
 * --------------------------------------------------------------
 *   ETH_PRIVATE_KEY   – 0x-prefixed funded account private key
 *   INFURA_API_KEY    – Infura project ID (for Sepolia / mainnet)
 *   ELECTION_ID       – Election identifier string (default: "GeneralElection2024")
 *
 * After deployment set in the Python environment:
 *   export ETH_RPC_URL=http://127.0.0.1:8545          # or Infura URL
 *   export ETH_CONTRACT_ADDR=<address printed below>
 *   export ETH_PRIVATE_KEY=<deployer private key>
 */

const { ethers } = require("hardhat");

async function main() {
  const electionId = process.env.ELECTION_ID || "GeneralElection2024";

  console.log(`\nDeploying VotingLedger for election: "${electionId}"`);

  const [deployer] = await ethers.getSigners();
  console.log(`Deployer address : ${deployer.address}`);
  const balance = await ethers.provider.getBalance(deployer.address);
  console.log(`Deployer balance : ${ethers.formatEther(balance)} ETH\n`);

  const VotingLedger = await ethers.getContractFactory("VotingLedger");
  const contract = await VotingLedger.deploy(electionId);
  await contract.waitForDeployment();

  const address = await contract.getAddress();
  console.log(`VotingLedger deployed to : ${address}`);
  console.log(`Election ID              : ${await contract.electionId()}`);
  console.log(`Authority                : ${await contract.authority()}`);
  console.log(`\nSet in your Python environment:`);
  console.log(`  export ETH_CONTRACT_ADDR=${address}`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
