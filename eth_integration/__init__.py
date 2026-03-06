"""
eth_integration — Ethereum Smart-Contract Bridge
=================================================
Anchors post-quantum voting evidence on an EVM-compatible blockchain.

Two backends are supported transparently:

  1. **In-memory EVM** (default, no external process needed)
     Uses ``eth-tester`` + ``py-evm``.  State is lost when the process
     exits.  Identical runtime to Hardhat's local node.

  2. **External Ethereum node** (production)
     Set the environment variable ``ETH_RPC_URL`` to a JSON-RPC endpoint
     (e.g. ``http://localhost:8545`` for Ganache/Hardhat, or an Infura URL).
     Deploy ``contracts/VotingLedger.sol`` first and set
     ``ETH_CONTRACT_ADDR`` to the deployed address.

The contract stores NO plaintext votes — only SHA3-256 hashes of
FHE ciphertexts, ZKP proofs, and nullifiers for double-vote prevention.
"""

from .bridge import EthBridge

__all__ = ["EthBridge"]
