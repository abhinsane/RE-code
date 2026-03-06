"""
Post-Quantum Secure Voting Blockchain
======================================
An immutable ledger for recording encrypted votes with the following
security properties:

Hash chain integrity
    Every block's SHA3-256 hash includes its predecessor's hash, so
    tampering with any block invalidates all subsequent hashes.

Merkle tree
    All vote records in a block are committed to a SHA3-256 Merkle tree.
    This allows efficient membership proofs without downloading the full
    block body.

ML-DSA-65 block signatures
    The election authority signs every mined block's (hash ‖ merkle_root)
    with its post-quantum ML-DSA-65 key.  Verifiers check the signature
    without needing the authority's secret key.

Proof-of-Work
    A small-difficulty PoW (configurable leading-zero count) prevents trivial
    block spamming.  It is not used for Sybil resistance in this permissioned
    setting; it only adds a modest tamper-evidence property.

Double-vote prevention
    A nullifier  SHA3(voter_id_hash ‖ voter_sig_pk)  is stored in a set.
    Any second submission from the same voter is silently rejected.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from typing import List, Optional

from .pq_crypto import pq_sign, pq_verify, sha3_256


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class VoteRecord:
    """
    An individual vote record stored on the blockchain.

    All fields referencing the actual vote are ciphertexts / hashes —
    no plaintext vote information is stored.
    """
    voter_id_hash:    str    # SHA3-256(voter_id) — privacy-preserving
    encrypted_vote:   str    # Hex-encoded FHE ciphertext
    zkp_commitment:   str    # Hex-encoded ZKP commitment (first 32 elems)
    zkp_proof_hash:   str    # SHA3-256 of full ZKP proof dict (hex)
    signature:        str    # ML-DSA-65 signature of (enc_vote ‖ zkp_hash)
    voter_sig_pk:     str    # Voter's ML-DSA-65 public key (hex)
    timestamp:        float = field(default_factory=time.time)

    def serialise(self) -> bytes:
        """Canonical byte representation for Merkle hashing.

        Previously the signature and voter_sig_pk fields were excluded, so an
        adversary who could mutate the stored blockchain data could swap out
        the voter's public key and signature in any VoteRecord without
        affecting the Merkle root or block hash.  Including them makes every
        field of every vote record committed by the block's Merkle root.
        """
        return json.dumps(
            {
                "voter_id_hash":  self.voter_id_hash,
                "encrypted_vote": self.encrypted_vote,
                "zkp_commitment": self.zkp_commitment,
                "zkp_proof_hash": self.zkp_proof_hash,
                "signature":      self.signature,
                "voter_sig_pk":   self.voter_sig_pk,
                "timestamp":      self.timestamp,
            },
            sort_keys=True,
        ).encode()


@dataclass
class Block:
    """
    A block in the post-quantum voting blockchain.

    Fields set at creation time
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~
    index, timestamp, prev_hash, votes, difficulty

    Fields computed during :meth:`mine`
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    merkle_root, nonce, hash

    Fields set after mining via :meth:`sign`
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    authority_signature
    """
    index:               int
    timestamp:           float
    prev_hash:           str
    votes:               List[VoteRecord]
    difficulty:          int = 2

    # Filled in by mine() / sign()
    merkle_root:         str = ""
    nonce:               int = 0
    hash:                str = ""
    authority_signature: str = ""

    # ------------------------------------------------------------------
    # Merkle tree
    # ------------------------------------------------------------------

    def compute_merkle_root(self) -> str:
        """SHA3-256 Merkle root of all vote records."""
        if not self.votes:
            return sha3_256(b"empty_block").hex()

        layer: List[bytes] = [sha3_256(v.serialise()) for v in self.votes]

        while len(layer) > 1:
            if len(layer) % 2:
                layer.append(layer[-1])   # duplicate last leaf
            layer = [
                sha3_256(layer[i] + layer[i + 1])
                for i in range(0, len(layer), 2)
            ]

        return layer[0].hex()

    # ------------------------------------------------------------------
    # Block hash
    # ------------------------------------------------------------------

    def _header_bytes(self) -> bytes:
        """Canonical header bytes for hashing (must be deterministic)."""
        header = {
            "index":       self.index,
            "timestamp":   self.timestamp,
            "prev_hash":   self.prev_hash,
            "merkle_root": self.merkle_root,
            "nonce":       self.nonce,
        }
        return json.dumps(header, sort_keys=True).encode()

    def compute_hash(self) -> str:
        return sha3_256(self._header_bytes()).hex()

    # ------------------------------------------------------------------
    # Proof-of-Work
    # ------------------------------------------------------------------

    def mine(self, difficulty: int) -> None:
        """
        Compute Merkle root then increment nonce until the block hash
        has *difficulty* leading hex zeros.
        """
        self.merkle_root = self.compute_merkle_root()
        target = "0" * difficulty
        self.nonce = 0
        while True:
            self.hash = self.compute_hash()
            if self.hash.startswith(target):
                return
            self.nonce += 1

    # ------------------------------------------------------------------
    # ML-DSA signature
    # ------------------------------------------------------------------

    def sign(self, authority_sig_sk: bytes) -> None:
        """Sign (hash ‖ merkle_root) with the authority's ML-DSA-65 key."""
        payload = (self.hash + self.merkle_root).encode()
        sig     = pq_sign(authority_sig_sk, payload)
        self.authority_signature = sig.hex()

    def verify_signature(self, authority_sig_pk: bytes) -> bool:
        """Verify the block's ML-DSA-65 signature."""
        if not self.authority_signature:
            return False
        payload = (self.hash + self.merkle_root).encode()
        sig     = bytes.fromhex(self.authority_signature)
        return pq_verify(authority_sig_pk, payload, sig)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        d = asdict(self)
        d["votes"] = [asdict(v) for v in self.votes]
        return d


# ---------------------------------------------------------------------------
# Blockchain
# ---------------------------------------------------------------------------

class VotingBlockchain:
    """
    Post-quantum secure blockchain for immutable vote storage.

    Usage
    -----
    1. Instantiate with the authority's ML-DSA-65 key pair.
    2. Call :meth:`add_vote` for each incoming vote.
    3. Call :meth:`mine_pending_votes` to commit a batch to a new block.
    4. Call :meth:`verify_chain` at any time to assert integrity.
    """

    def __init__(
        self,
        authority_sig_sk: bytes,
        authority_sig_pk: bytes,
        difficulty: int = 2,
    ) -> None:
        self._sk:             bytes              = authority_sig_sk
        self._pk:             bytes              = authority_sig_pk
        self.difficulty:      int                = difficulty
        self.chain:           List[Block]        = []
        self.pending_votes:   List[VoteRecord]   = []
        self._nullifiers:     set                = set()

        self._create_genesis()

    # ------------------------------------------------------------------
    # Genesis block
    # ------------------------------------------------------------------

    def _create_genesis(self) -> None:
        genesis = Block(
            index=0,
            timestamp=time.time(),
            prev_hash="0" * 64,
            votes=[],
            difficulty=self.difficulty,
        )
        genesis.mine(self.difficulty)
        genesis.sign(self._sk)
        self.chain.append(genesis)

    # ------------------------------------------------------------------
    # Vote ingestion
    # ------------------------------------------------------------------

    def add_vote(self, record: VoteRecord) -> bool:
        """
        Add a vote record to the pending pool.

        Returns False (and discards the record) if the nullifier is already
        present (double-vote attempt).
        """
        # Nullifier is based only on voter_id_hash.
        # Previously voter_sig_pk was included, allowing a voter who somehow
        # obtained a second registration with a different key pair to cast a
        # second vote (different nullifier despite same voter identity).
        # The voter_id is the authoritative unique identity; keying the
        # nullifier on it alone closes this gap.
        nullifier = sha3_256(bytes.fromhex(record.voter_id_hash)).hex()

        if nullifier in self._nullifiers:
            return False

        self._nullifiers.add(nullifier)
        self.pending_votes.append(record)
        return True

    # ------------------------------------------------------------------
    # Block mining
    # ------------------------------------------------------------------

    def mine_pending_votes(self) -> Optional[Block]:
        """
        Bundle all pending votes into a new block, mine it, sign it,
        and append it to the chain.

        Returns the new block, or None if there are no pending votes.
        """
        if not self.pending_votes:
            return None

        block = Block(
            index=len(self.chain),
            timestamp=time.time(),
            prev_hash=self.chain[-1].hash,
            votes=list(self.pending_votes),
            difficulty=self.difficulty,
        )
        block.mine(self.difficulty)
        block.sign(self._sk)

        self.chain.append(block)
        self.pending_votes.clear()
        return block

    # ------------------------------------------------------------------
    # Chain verification
    # ------------------------------------------------------------------

    def verify_chain(self) -> bool:
        """
        Full chain integrity check.

        Verifies the genesis block and for every subsequent block:
        * stored hash matches recomputed hash
        * PoW target (leading zeros) is satisfied
        * ML-DSA-65 authority signature is valid
        * prev_hash correctly references the predecessor's hash

        Previously the genesis block (index 0) was never verified, allowing
        an adversary to silently replace it (different initial state, forged
        prev_hash of "0"*64, etc.) without failing the integrity check.
        """
        if not self.chain:
            return True

        # Verify genesis block
        genesis = self.chain[0]
        if genesis.hash != genesis.compute_hash():
            return False
        if not genesis.hash.startswith("0" * genesis.difficulty):
            return False
        if not genesis.verify_signature(self._pk):
            return False

        for i in range(1, len(self.chain)):
            cur  = self.chain[i]
            prev = self.chain[i - 1]

            if cur.prev_hash != prev.hash:
                return False
            if cur.hash != cur.compute_hash():
                return False
            if not cur.hash.startswith("0" * cur.difficulty):
                return False
            if not cur.verify_signature(self._pk):
                return False
            # Re-derive Merkle root from the actual vote records and compare
            # to the stored value.  compute_hash() uses the stored merkle_root
            # string verbatim, so without this check an adversary can replace
            # vote records within a block while leaving the block hash intact.
            if cur.merkle_root != cur.compute_merkle_root():
                return False

        return True

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    def all_votes(self) -> List[VoteRecord]:
        """Return every vote record committed on-chain (genesis excluded)."""
        result = []
        for block in self.chain[1:]:
            result.extend(block.votes)
        return result

    def stats(self) -> dict:
        return {
            "chain_length":  len(self.chain),
            "total_votes":   len(self.all_votes()),
            "pending_votes": len(self.pending_votes),
            "chain_valid":   self.verify_chain(),
        }
