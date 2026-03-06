"""
Post-Quantum E-Voting System — Main Orchestrator
==================================================
Integrates all cryptographic components into a complete election lifecycle:

  Phase 0 – Setup
      The :class:`ElectionAuthority` generates its PQ key pair, sets up
      the FHE context (TenSEAL BFV), the lattice-based ZKP system, and
      mines the genesis block of the voting blockchain.

  Phase 1 – Voter Registration
      Each voter generates their own PQ key pair (:class:`Voter`).
      The authority enrolls their cancellable biometric template
      (BioHash of a SOCOFing fingerprint encrypted with ML-KEM-768).

  Phase 2 – Authentication & Voting
      Before casting a ballot the voter is authenticated biometrically.
      The voter:
        a) FHE-encrypts their choice as a one-hot BFV vector.
        b) Generates a lattice-based ZKP proving the choice is valid
           (in range) without revealing it.
        c) Signs the (ciphertext ‖ ZKP-hash) with their ML-DSA-65 key.
        d) Submits the signed ballot package to the authority.

  Phase 3 – Vote Reception & Validation
      The authority:
        a) Checks the voter is registered, active, and has not yet voted.
        b) Verifies the ML-DSA-65 signature.
        c) Verifies the ZKP.
        d) Adds the FHE ciphertext to the homomorphic tally (never decrypts).
        e) Records a :class:`VoteRecord` on the blockchain.
        f) Marks the voter as having voted.

  Phase 4 – Tallying & Result Publication
      After polls close the authority:
        a) Mines any remaining pending votes into a block.
        b) Verifies the full blockchain.
        c) Decrypts the FHE tally (one decryption for all votes combined).
        d) Signs the result set with ML-DSA-65.
        e) Returns a publicly verifiable result package.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Dict, List, Optional, Tuple

from .blockchain import VoteRecord, VotingBlockchain
from .cancellable_biometric import CancellableBiometric
from .fhe_voting import FHEAuthority, FHEVoter, FHETally
from .pq_crypto import PQKeyPair, pq_sign, pq_verify, sha3_256
from .voter import VoterRegistration, VoterRegistry
from .zkp import LatticeZKP


# ---------------------------------------------------------------------------
# Election configuration
# ---------------------------------------------------------------------------

class ElectionConfig:
    """Immutable election configuration."""

    def __init__(self, election_id: str, candidates: List[str]) -> None:
        if len(candidates) < 2:
            raise ValueError("An election requires at least 2 candidates.")
        self.election_id       = election_id
        self.election_id_bytes = election_id.encode()
        self.candidates        = list(candidates)
        self.num_candidates    = len(candidates)


# ---------------------------------------------------------------------------
# Election authority
# ---------------------------------------------------------------------------

class ElectionAuthority:
    """
    Manages the entire election lifecycle on the authority side.

    Holds ALL secret key material (FHE secret key, PQ secret keys).
    In a real deployment this entity would be a threshold multi-party
    committee; here it is a single trusted party for prototype purposes.
    """

    def __init__(self, config: ElectionConfig) -> None:
        self.config = config
        self._active    = True
        self._finalized = False

        print("[Authority] Generating post-quantum key pair (ML-KEM-768 + ML-DSA-65) …")
        self._kp = PQKeyPair()

        print("[Authority] Setting up FHE context (TenSEAL BFV) …")
        self._fhe      = FHEAuthority(config.num_candidates)
        self._tally    = FHETally(self._fhe)

        print("[Authority] Initialising lattice-based ZKP system …")
        self._zkp      = LatticeZKP(config.num_candidates)

        print("[Authority] Initialising blockchain …")
        self._chain    = VotingBlockchain(
            self._kp.sig_sk, self._kp.sig_pk, difficulty=2
        )

        self._bio      = CancellableBiometric()
        self._registry = VoterRegistry()

        print(
            f"[Authority] Election '{config.election_id}' ready.  "
            f"Candidates: {config.candidates}"
        )

    # ------------------------------------------------------------------
    # Public parameter broadcast
    # ------------------------------------------------------------------

    def public_params(self) -> dict:
        """
        Return all public parameters that voters need to encrypt their
        votes and generate ZKPs.  Contains NO secret material.
        """
        return {
            "election_id":        self.config.election_id,
            "candidates":         self.config.candidates,
            "num_candidates":     self.config.num_candidates,
            "authority_kem_pk":   self._kp.kem_pk,
            "authority_sig_pk":   self._kp.sig_pk,
            "fhe_public_context": self._fhe.public_context_bytes(),
        }

    # ------------------------------------------------------------------
    # Voter registration
    # ------------------------------------------------------------------

    def register_voter(
        self,
        voter_id: str,
        voter_kem_pk: bytes,
        voter_sig_pk: bytes,
        fingerprint_path: str,
        user_token: bytes,
    ) -> VoterRegistration:
        """
        Enrol a new voter.

        Parameters
        ----------
        voter_id         : Unique identifier (UUID string recommended).
        voter_kem_pk     : Voter's ML-KEM-768 public key.
        voter_sig_pk     : Voter's ML-DSA-65  public key.
        fingerprint_path : Path to voter's SOCOFing fingerprint image.
        user_token       : Secret token (e.g. SHA3-256 of PIN) for
                           cancellable biometric.  The authority only
                           stores a hash of this token.
        """
        print(f"[Authority] Enrolling voter {voter_id[:8]}… ")
        bio_data = self._bio.enroll(
            fingerprint_path, user_token, self._kp.kem_pk
        )
        reg = VoterRegistration(
            voter_id=voter_id,
            kem_pk=voter_kem_pk,
            sig_pk=voter_sig_pk,
            biometric_data=bio_data,
        )
        if not self._registry.register(reg):
            raise ValueError(f"Voter {voter_id} is already registered.")
        print(f"[Authority]   → voter {voter_id[:8]}… enrolled. ✓")
        return reg

    # ------------------------------------------------------------------
    # Biometric authentication
    # ------------------------------------------------------------------

    def authenticate(
        self,
        voter_id: str,
        fingerprint_path: str,
        user_token: bytes,
    ) -> Tuple[bool, float]:
        """
        Biometrically authenticate a voter before letting them vote.

        Returns (ok, similarity_score).
        """
        reg = self._registry.get(voter_id)
        if reg is None or not reg.is_active:
            return False, 0.0
        if reg.has_voted:
            print(f"[Authority] Voter {voter_id[:8]}… already voted — rejected.")
            return False, 0.0

        ok, score = self._bio.verify(
            fingerprint_path, user_token,
            self._kp.kem_sk, reg.biometric_data,
        )
        return ok, score

    # ------------------------------------------------------------------
    # Vote reception
    # ------------------------------------------------------------------

    def receive_vote(self, submission: dict) -> bool:
        """
        Accept, validate, and record an incoming vote submission.

        Expected keys in *submission*
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        voter_id             : str
        encrypted_vote_hex   : str  (hex-encoded FHE ciphertext)
        zkp_proof            : dict (full ZKP proof)
        zkp_commitment       : str  (hex)
        zkp_proof_hash       : str  (hex)
        signature            : str  (hex, ML-DSA-65 over enc_vote ‖ zkp_hash)

        Returns True iff the vote was successfully recorded.
        """
        voter_id = submission.get("voter_id", "")
        reg = self._registry.get(voter_id)

        # ---- Eligibility -------------------------------------------------
        if reg is None or not reg.is_active or reg.has_voted:
            print(f"[Authority] Vote rejected — voter ineligible: {voter_id[:8]}…")
            return False

        # ---- ML-DSA-65 signature -----------------------------------------
        sig_payload = (
            submission["encrypted_vote_hex"] + submission["zkp_proof_hash"]
        ).encode()
        if not pq_verify(
            reg.sig_pk,
            sig_payload,
            bytes.fromhex(submission["signature"]),
        ):
            print(f"[Authority] Vote rejected — invalid signature: {voter_id[:8]}…")
            return False

        # ---- ZKP verification --------------------------------------------
        if not self._zkp.verify_vote_proof(
            submission["zkp_proof"],
            voter_id.encode(),
            self.config.election_id_bytes,
        ):
            print(f"[Authority] Vote rejected — ZKP invalid: {voter_id[:8]}…")
            return False

        # ---- FHE tally ---------------------------------------------------
        enc_bytes = bytes.fromhex(submission["encrypted_vote_hex"])
        self._tally.add_encrypted_vote(enc_bytes)

        # ---- Blockchain --------------------------------------------------
        record = VoteRecord(
            voter_id_hash=reg.voter_id_hash,
            encrypted_vote=submission["encrypted_vote_hex"],
            zkp_commitment=submission["zkp_commitment"],
            zkp_proof_hash=submission["zkp_proof_hash"],
            signature=submission["signature"],
            voter_sig_pk=reg.sig_pk.hex(),
        )
        if not self._chain.add_vote(record):
            print(f"[Authority] Duplicate nullifier — vote rejected: {voter_id[:8]}…")
            return False

        # ---- Mark voter --------------------------------------------------
        self._registry.mark_voted(voter_id)
        print(f"[Authority] Vote accepted and recorded. Voter: {voter_id[:8]}…")
        return True

    # ------------------------------------------------------------------
    # Election finalisation
    # ------------------------------------------------------------------

    def finalize(self) -> dict:
        """
        Close the election and compute final results.

        Steps
        -----
        1. Mine any pending votes into a final block.
        2. Verify the full blockchain.
        3. Decrypt the FHE tally (single decryption operation).
        4. Sign the results with ML-DSA-65.
        5. Return a fully verifiable result package.
        """
        if self._finalized:
            raise RuntimeError("Election has already been finalised.")

        print("\n[Authority] ─── Finalising election ───")

        # Mine remaining votes
        blk = self._chain.mine_pending_votes()
        if blk:
            print(
                f"[Authority] Mined block #{blk.index} "
                f"({len(blk.votes)} votes)"
            )

        # Verify chain
        chain_ok = self._chain.verify_chain()
        print(
            f"[Authority] Blockchain integrity: "
            f"{'VALID ✓' if chain_ok else 'INVALID ✗'}"
        )

        # Decrypt FHE tally
        tally = self._tally.finalize()
        counts = tally["per_candidate"]
        total  = tally["total_votes"]

        # Build results dict
        results_by_name = {
            self.config.candidates[i]: counts[i]
            for i in range(self.config.num_candidates)
        }
        winner_idx  = max(counts, key=lambda k: counts[k])
        winner_name = self.config.candidates[winner_idx]

        result = {
            "election_id":    self.config.election_id,
            "candidates":     self.config.candidates,
            "results":        results_by_name,
            "total_votes":    total,
            "winner":         winner_name,
            "blockchain_ok":  chain_ok,
            "chain_length":   len(self._chain.chain),
            "timestamp":      time.time(),
        }

        # Sign results
        result_bytes = json.dumps(result, sort_keys=True).encode()
        sig          = pq_sign(self._kp.sig_sk, result_bytes)
        result["authority_signature"] = sig.hex()
        result["authority_sig_pk"]    = self._kp.sig_pk.hex()

        self._finalized = True
        self._active    = False

        # Print summary
        print("\n[Authority] ══════ ELECTION RESULTS ══════")
        for name, cnt in results_by_name.items():
            pct = (cnt / total * 100) if total else 0
            print(f"  {name:<25} {cnt:>4} votes  ({pct:.1f} %)")
        print(f"\n  Winner  : {winner_name}")
        print(f"  Total   : {total}")
        print(f"  Signed with ML-DSA-65 ✓")

        return result

    # ------------------------------------------------------------------
    # Blockchain statistics
    # ------------------------------------------------------------------

    def chain_stats(self) -> dict:
        return self._chain.stats()


# ---------------------------------------------------------------------------
# Voter client
# ---------------------------------------------------------------------------

class Voter:
    """
    Voter client — handles key generation, vote encryption, ZKP, and signing.

    The voter holds their own ML-KEM + ML-DSA secret keys locally;
    these are never transmitted to the authority.
    """

    def __init__(self, voter_id: str, public_params: dict) -> None:
        self.voter_id       = voter_id
        self._id_bytes      = voter_id.encode()
        self._params        = public_params

        print(f"[Voter {voter_id[:8]}…] Generating PQ key pair …")
        self._kp  = PQKeyPair()

        self._fhe = FHEVoter(
            public_params["fhe_public_context"],
            public_params["num_candidates"],
        )
        self._zkp = LatticeZKP(public_params["num_candidates"])
        print(f"[Voter {voter_id[:8]}…] Ready.")

    # ------------------------------------------------------------------
    # Public key accessors (for registration)
    # ------------------------------------------------------------------

    @property
    def kem_pk(self) -> bytes:
        return self._kp.kem_pk

    @property
    def sig_pk(self) -> bytes:
        return self._kp.sig_pk

    # ------------------------------------------------------------------
    # Ballot casting
    # ------------------------------------------------------------------

    def cast_vote(self, candidate_idx: int) -> dict:
        """
        Prepare a fully encrypted, ZK-proved, signed ballot package.

        Steps
        -----
        1. FHE-encrypt the vote as a one-hot BFV vector.
        2. Generate a lattice-based ZKP proving the choice is in range.
        3. Sign (FHE_ct_hex ‖ zkp_hash) with ML-DSA-65.

        Returns a dict ready to pass to :meth:`ElectionAuthority.receive_vote`.
        """
        election_id = self._params["election_id"].encode()

        # ---- Step 1: FHE encryption ------------------------------------
        enc_bytes = self._fhe.encrypt_vote(candidate_idx)
        enc_hex   = enc_bytes.hex()
        print(f"[Voter {self.voter_id[:8]}…] Vote FHE-encrypted (BFV one-hot).")

        # ---- Step 2: Lattice ZKP ---------------------------------------
        zkp_proof      = self._zkp.prove_vote_range(
            candidate_idx, self._id_bytes, election_id
        )
        zkp_commitment = bytes(
            self._zkp.commitment_bytes(zkp_proof)
        ).hex()
        zkp_proof_hash = sha3_256(
            json.dumps(zkp_proof, sort_keys=True).encode()
        ).hex()
        print(f"[Voter {self.voter_id[:8]}…] Lattice ZKP generated.")

        # ---- Step 3: ML-DSA-65 signature --------------------------------
        sig_payload = (enc_hex + zkp_proof_hash).encode()
        signature   = pq_sign(self._kp.sig_sk, sig_payload)
        print(f"[Voter {self.voter_id[:8]}…] Ballot signed with ML-DSA-65.")

        return {
            "voter_id":           self.voter_id,
            "encrypted_vote_hex": enc_hex,
            "zkp_proof":          zkp_proof,
            "zkp_commitment":     zkp_commitment,
            "zkp_proof_hash":     zkp_proof_hash,
            "signature":          signature.hex(),
        }
