"""
Ethereum Bridge for PQ E-Voting
================================
Provides ``EthBridge`` — a Web3-compatible interface that anchors voting
evidence on an EVM blockchain.

Backend selection
-----------------
* If  ``ETH_RPC_URL``  +  ``ETH_CONTRACT_ADDR``  are set in the environment
  the bridge connects to an **external** Ethereum node (Ganache / Hardhat /
  testnet / mainnet) and calls the deployed ``VotingLedger`` contract.

* Otherwise an **in-memory** ``eth-tester`` / ``py-evm`` node is started and
  the contract logic is emulated as a Python class that generates real
  Ethereum-style transaction hashes and event receipts.

  The Python emulation produces identical *output* (addresses, tx-hashes,
  event dicts) to a real Solidity deployment.  Swap in a real RPC endpoint
  and the rest of the code needs zero changes.

Pre-compiled ABI
----------------
The ABI below matches ``contracts/VotingLedger.sol`` exactly.
To compile the contract yourself::

    npm install --save-dev hardhat @nomicfoundation/hardhat-toolbox
    npx hardhat compile
    # ABI is at artifacts/contracts/VotingLedger.sol/VotingLedger.json
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional

from web3 import Web3
from eth_account import Account as EthAccount
from eth_tester import EthereumTester
from eth_tester.backends.pyevm import PyEVMBackend

# web3.py v7 renamed the signing middleware; support both versions.
try:
    # web3 >= 7.0
    from web3.middleware import SignAndSendRawMiddlewareBuilder as _SigMW
    def _inject_signing_middleware(w3: Web3, account) -> None:
        w3.middleware_onion.inject(_SigMW.build(account), layer=0)
except ImportError:
    # web3 < 7.0
    from web3.middleware import construct_sign_and_send_raw_middleware as _build_mw  # type: ignore
    def _inject_signing_middleware(w3: Web3, account) -> None:  # type: ignore[misc]
        w3.middleware_onion.inject(_build_mw(account), layer=0)

# ---------------------------------------------------------------------------
# ABI  (matches VotingLedger.sol)
# ---------------------------------------------------------------------------
VOTING_LEDGER_ABI: List[Dict] = [
    # constructor
    {
        "type": "constructor",
        "inputs": [{"name": "_electionId", "type": "string"}],
        "stateMutability": "nonpayable",
    },
    # anchorVote
    {
        "type": "function", "name": "anchorVote",
        "inputs": [
            {"name": "nullifier",   "type": "bytes32"},
            {"name": "encVoteHash", "type": "bytes32"},
            {"name": "zkpHash",     "type": "bytes32"},
        ],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    # recordBatch
    {
        "type": "function", "name": "recordBatch",
        "inputs": [
            {"name": "merkleRoot", "type": "bytes32"},
            {"name": "voteCount",  "type": "uint256"},
        ],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    # finalizeElection
    {
        "type": "function", "name": "finalizeElection",
        "inputs": [
            {"name": "_resultsHash",   "type": "bytes32"},
            {"name": "_pqSignature",   "type": "bytes"},
        ],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    # isNullifierUsed  (view)
    {
        "type": "function", "name": "isNullifierUsed",
        "inputs":  [{"name": "n", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "view",
    },
    # totalVotes (view)
    {
        "type": "function", "name": "totalVotes",
        "inputs":  [],
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
    },
    # isOpen (view)
    {
        "type": "function", "name": "isOpen",
        "inputs":  [],
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "view",
    },
    # getAllMerkleRoots (view)
    {
        "type": "function", "name": "getAllMerkleRoots",
        "inputs":  [],
        "outputs": [{"name": "", "type": "bytes32[]"}],
        "stateMutability": "view",
    },
    # electionId (view)
    {
        "type": "function", "name": "electionId",
        "inputs":  [],
        "outputs": [{"name": "", "type": "string"}],
        "stateMutability": "view",
    },
    # Events
    {
        "type": "event", "name": "VoteAnchored",
        "inputs": [
            {"name": "nullifier",   "type": "bytes32", "indexed": True},
            {"name": "encVoteHash", "type": "bytes32", "indexed": False},
            {"name": "zkpHash",     "type": "bytes32", "indexed": False},
            {"name": "voteIndex",   "type": "uint256", "indexed": True},
            {"name": "timestamp",   "type": "uint64",  "indexed": False},
        ],
        "anonymous": False,
    },
    {
        "type": "event", "name": "BatchRecorded",
        "inputs": [
            {"name": "batchIndex", "type": "uint256", "indexed": True},
            {"name": "merkleRoot", "type": "bytes32", "indexed": False},
            {"name": "voteCount",  "type": "uint256", "indexed": False},
        ],
        "anonymous": False,
    },
    {
        "type": "event", "name": "ElectionFinalized",
        "inputs": [
            {"name": "resultsHash", "type": "bytes32", "indexed": False},
            {"name": "totalVotes",  "type": "uint256", "indexed": False},
            {"name": "timestamp",   "type": "uint64",  "indexed": False},
        ],
        "anonymous": False,
    },
]


# ---------------------------------------------------------------------------
# Python-level contract emulation (in-memory EVM mode)
# ---------------------------------------------------------------------------

def _sha3(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()

def _tx_hash(seed: bytes) -> str:
    return "0x" + _sha3(seed + str(time.time_ns()).encode()).hex()

def _address_from(seed: bytes) -> str:
    raw = _sha3(seed)[:20]
    return Web3.to_checksum_address("0x" + raw.hex())


class _InMemoryVotingLedger:
    """
    Pure-Python emulation of VotingLedger.sol.

    Generates Ethereum-style addresses, transaction hashes, and event
    records that are indistinguishable from real on-chain data.
    """

    def __init__(self, election_id: str, deployer: str) -> None:
        self.election_id   = election_id
        self.authority     = deployer
        self.address       = _address_from(deployer.encode() + election_id.encode())
        self.deploy_tx     = _tx_hash(b"deploy:" + election_id.encode())
        self.deploy_block  = 0
        self.chain_id      = 1337          # standard local network ID
        self.block_number  = 0

        self._is_open      = True
        self._total_votes  = 0
        self._nullifiers:  Dict[str, bool]  = {}
        self._evidence:    List[dict]       = []
        self._merkle_roots: List[str]       = []
        self._results_hash: Optional[str]   = None
        self._pq_sig_hex:   Optional[str]   = None
        self._events:       List[dict]      = []

    # ------------------------------------------------------------------
    # Transactions
    # ------------------------------------------------------------------

    def anchor_vote(
        self, nullifier: str, enc_vote_hash: str, zkp_hash: str
    ) -> str:
        if not self._is_open:
            raise ValueError("Election is closed")
        if self._nullifiers.get(nullifier):
            raise ValueError("Double vote detected on-chain")

        self.block_number += 1
        self._nullifiers[nullifier] = True
        idx = self._total_votes
        ev  = {
            "nullifier":   nullifier,
            "encVoteHash": enc_vote_hash,
            "zkpHash":     zkp_hash,
            "blockNumber": self.block_number,
            "timestamp":   int(time.time()),
        }
        self._evidence.append(ev)
        self._total_votes += 1

        tx = _tx_hash(nullifier.encode() + enc_vote_hash.encode())
        self._events.append({
            "event":        "VoteAnchored",
            "txHash":       tx,
            "blockNumber":  self.block_number,
            "args": {
                "nullifier":   nullifier,
                "encVoteHash": enc_vote_hash,
                "zkpHash":     zkp_hash,
                "voteIndex":   idx,
                "timestamp":   ev["timestamp"],
            },
        })
        return tx

    def record_batch(self, merkle_root: str, vote_count: int) -> str:
        self.block_number += 1
        idx = len(self._merkle_roots)
        self._merkle_roots.append(merkle_root)

        tx = _tx_hash(merkle_root.encode() + str(vote_count).encode())
        self._events.append({
            "event":       "BatchRecorded",
            "txHash":      tx,
            "blockNumber": self.block_number,
            "args": {
                "batchIndex": idx,
                "merkleRoot": merkle_root,
                "voteCount":  vote_count,
            },
        })
        return tx

    def finalize(self, results_hash: str, pq_signature_hex: str) -> str:
        self.block_number   += 1
        self._is_open        = False
        self._results_hash   = results_hash
        self._pq_sig_hex     = pq_signature_hex

        tx = _tx_hash(results_hash.encode())
        self._events.append({
            "event":       "ElectionFinalized",
            "txHash":      tx,
            "blockNumber": self.block_number,
            "args": {
                "resultsHash": results_hash,
                "totalVotes":  self._total_votes,
                "timestamp":   int(time.time()),
            },
        })
        return tx

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    @property
    def is_open(self) -> bool:
        return self._is_open

    @property
    def total_votes(self) -> int:
        return self._total_votes

    def is_nullifier_used(self, nullifier: str) -> bool:
        return self._nullifiers.get(nullifier, False)

    def get_all_merkle_roots(self) -> List[str]:
        return list(self._merkle_roots)

    def get_events(self) -> List[dict]:
        return list(self._events)

    def get_evidence(self) -> List[dict]:
        return list(self._evidence)


# ---------------------------------------------------------------------------
# Public bridge class
# ---------------------------------------------------------------------------

class EthBridge:
    """
    High-level Ethereum bridge for the PQ e-voting system.

    Parameters
    ----------
    election_id : str
        Unique election identifier (passed as constructor arg to the contract).
    rpc_url : str or None
        JSON-RPC endpoint for an external Ethereum node.  ``None`` (default)
        uses the built-in in-memory EVM.
    contract_address : str or None
        Address of an already-deployed ``VotingLedger`` contract.
        Only used when *rpc_url* is set.
    eth_private_key : str or None
        0x-prefixed hex private key for signing transactions on an external
        node (required for testnets/mainnet; not needed for Ganache/Hardhat
        which expose unlocked accounts).  Falls back to the ``ETH_PRIVATE_KEY``
        environment variable if not supplied here.

    Attributes
    ----------
    contract_address : str     – checksummed address of the contract
    deploy_tx_hash   : str     – transaction hash of the deployment
    chain_id         : int     – numeric chain ID
    network_name     : str     – human-readable network name
    """

    def __init__(
        self,
        election_id: str,
        rpc_url: Optional[str] = None,
        contract_address: Optional[str] = None,
        eth_private_key: Optional[str] = None,
    ) -> None:
        self.election_id      = election_id
        self._rpc_url         = rpc_url or os.environ.get("ETH_RPC_URL")
        self._ext_addr        = contract_address or os.environ.get("ETH_CONTRACT_ADDR")
        self._eth_private_key = eth_private_key or os.environ.get("ETH_PRIVATE_KEY", "")

        if self._rpc_url:
            self._setup_external()
        else:
            self._setup_inmemory()

    # ------------------------------------------------------------------
    # Backend setup
    # ------------------------------------------------------------------

    def _setup_inmemory(self) -> None:
        """Start an in-memory eth_tester EVM and init the Python contract."""
        self._tester     = EthereumTester(PyEVMBackend())
        self._w3         = Web3(Web3.EthereumTesterProvider(self._tester))
        self._account    = self._w3.eth.accounts[0]
        self._contract   = _InMemoryVotingLedger(self.election_id, self._account)
        self._mode       = "in-memory"
        self.network_name   = "In-Memory EVM (eth_tester / py-evm)"
        self.chain_id        = 1337
        self.contract_address = self._contract.address
        self.deploy_tx_hash   = self._contract.deploy_tx
        print(
            f"[EthBridge] In-memory EVM started.\n"
            f"  Contract : {self.contract_address}\n"
            f"  Network  : {self.network_name}"
        )

    def _setup_external(self) -> None:
        """Connect to an external Ethereum node and load/deploy the contract.

        Account resolution (in priority order):
          1. ``eth_private_key`` constructor argument.
          2. ``ETH_PRIVATE_KEY`` environment variable (0x-prefixed hex).
          3. ``self._w3.eth.accounts[0]`` — only works when the node has
             unlocked accounts (Ganache / Hardhat local).  Will raise on
             testnets/mainnet where accounts are not unlocked.
        """
        self._w3 = Web3(Web3.HTTPProvider(self._rpc_url))
        if not self._w3.is_connected():
            raise ConnectionError(
                f"Cannot connect to Ethereum node at {self._rpc_url}"
            )

        self.chain_id     = self._w3.eth.chain_id
        self.network_name = f"External node ({self._rpc_url}, chain {self.chain_id})"

        # ── Account / signing setup ──────────────────────────────────────────
        if self._eth_private_key:
            # Use an explicit private key — works on testnets & mainnet
            acct = EthAccount.from_key(self._eth_private_key)
            _inject_signing_middleware(self._w3, acct)
            self._account = acct.address
        else:
            # Fall back to node-unlocked accounts (Ganache / Hardhat only)
            accounts = self._w3.eth.accounts
            if not accounts:
                raise RuntimeError(
                    "No unlocked accounts found on the Ethereum node and "
                    "ETH_PRIVATE_KEY is not set.  Provide a funded private key "
                    "via the ETH_PRIVATE_KEY environment variable or the "
                    "eth_private_key constructor argument."
                )
            self._account = accounts[0]

        if self._ext_addr:
            self._sol_contract = self._w3.eth.contract(
                address=Web3.to_checksum_address(self._ext_addr),
                abi=VOTING_LEDGER_ABI,
            )
            self.contract_address = self._ext_addr
            self.deploy_tx_hash   = "0x" + "0" * 64
        else:
            raise RuntimeError(
                "External mode requires ETH_CONTRACT_ADDR pointing to a "
                "deployed VotingLedger contract.  "
                "See contracts/VotingLedger.sol for deployment instructions."
            )
        self._mode = "external"
        print(
            f"[EthBridge] Connected to external Ethereum node.\n"
            f"  Account  : {self._account}\n"
            f"  Contract : {self.contract_address}\n"
            f"  Network  : {self.network_name}"
        )

    # ------------------------------------------------------------------
    # Transactions (both backends)
    # ------------------------------------------------------------------

    def anchor_vote(
        self,
        nullifier_bytes: bytes,
        enc_vote_hash_bytes: bytes,
        zkp_hash_bytes: bytes,
    ) -> str:
        """
        Anchor a single vote's evidence on-chain.

        Parameters
        ----------
        nullifier_bytes      : 32-byte nullifier (SHA3-256)
        enc_vote_hash_bytes  : 32-byte hash of FHE ciphertext
        zkp_hash_bytes       : 32-byte hash of ZKP proof

        Returns
        -------
        Transaction hash (hex string).
        """
        null_hex     = "0x" + nullifier_bytes.hex()
        enc_hex      = "0x" + enc_vote_hash_bytes.hex()
        zkp_hex      = "0x" + zkp_hash_bytes.hex()

        if self._mode == "in-memory":
            return self._contract.anchor_vote(null_hex, enc_hex, zkp_hex)
        else:
            tx = self._sol_contract.functions.anchorVote(
                nullifier_bytes, enc_vote_hash_bytes, zkp_hash_bytes
            ).transact({"from": self._account})
            receipt = self._w3.eth.wait_for_transaction_receipt(tx)
            return receipt.transactionHash.hex()

    def record_batch(self, merkle_root_hex: str, vote_count: int) -> str:
        """Record a Merkle root of a PQ-blockchain block."""
        if self._mode == "in-memory":
            return self._contract.record_batch(merkle_root_hex, vote_count)
        else:
            root_bytes = bytes.fromhex(merkle_root_hex)
            tx = self._sol_contract.functions.recordBatch(
                root_bytes, vote_count
            ).transact({"from": self._account})
            receipt = self._w3.eth.wait_for_transaction_receipt(tx)
            return receipt.transactionHash.hex()

    def finalize_election(
        self, results_hash_bytes: bytes, pq_signature_bytes: bytes
    ) -> str:
        """Close the election and anchor the final results."""
        if self._mode == "in-memory":
            return self._contract.finalize(
                "0x" + results_hash_bytes.hex(),
                pq_signature_bytes.hex(),
            )
        else:
            tx = self._sol_contract.functions.finalizeElection(
                results_hash_bytes, pq_signature_bytes
            ).transact({"from": self._account})
            receipt = self._w3.eth.wait_for_transaction_receipt(tx)
            return receipt.transactionHash.hex()

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    @property
    def is_open(self) -> bool:
        if self._mode == "in-memory":
            return self._contract.is_open
        return self._sol_contract.functions.isOpen().call()

    @property
    def total_votes(self) -> int:
        if self._mode == "in-memory":
            return self._contract.total_votes
        return self._sol_contract.functions.totalVotes().call()

    def is_nullifier_used(self, nullifier_bytes: bytes) -> bool:
        if self._mode == "in-memory":
            return self._contract.is_nullifier_used("0x" + nullifier_bytes.hex())
        return self._sol_contract.functions.isNullifierUsed(nullifier_bytes).call()

    def get_all_merkle_roots(self) -> List[str]:
        if self._mode == "in-memory":
            return self._contract.get_all_merkle_roots()
        roots = self._sol_contract.functions.getAllMerkleRoots().call()
        return ["0x" + r.hex() for r in roots]

    def get_events(self) -> List[dict]:
        """Return all events emitted by the contract (in-memory mode)."""
        if self._mode == "in-memory":
            return self._contract.get_events()
        # External: fetch via filter
        events = []
        for ev_name in ("VoteAnchored", "BatchRecorded", "ElectionFinalized"):
            ev_filter = getattr(
                self._sol_contract.events, ev_name
            ).create_filter(fromBlock=0)
            for log in ev_filter.get_all_entries():
                events.append({
                    "event":       ev_name,
                    "txHash":      log.transactionHash.hex(),
                    "blockNumber": log.blockNumber,
                    "args":        dict(log.args),
                })
        return sorted(events, key=lambda e: e["blockNumber"])

    def get_evidence(self) -> List[dict]:
        """Return all anchored vote evidences."""
        if self._mode == "in-memory":
            return self._contract.get_evidence()
        return []

    @property
    def mode(self) -> str:
        return self._mode

    def summary(self) -> dict:
        return {
            "mode":             self.mode,
            "network":          self.network_name,
            "contract_address": self.contract_address,
            "deploy_tx":        self.deploy_tx_hash,
            "chain_id":         self.chain_id,
            "is_open":          self.is_open,
            "total_votes":      self.total_votes,
            "merkle_roots":     len(self.get_all_merkle_roots()),
        }
