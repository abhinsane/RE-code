"""
Fully Homomorphic Encryption (FHE) Voting Module
=================================================
Uses TenSEAL's BFV (Brakerski-Fan-Vercauteren) scheme for encrypted vote
tallying.  Votes are **never decrypted during accumulation** — only the
election authority can reveal the final tally after the polls close.

Architecture
------------
* **FHEAuthority** – holds the BFV secret key; sets up the context and
  exports a *public* context for voters.
* **FHEVoter** – uses only the public context to encrypt individual votes
  as one-hot vectors.
* **FHETally** – homomorphically sums all encrypted vote vectors; the
  authority decrypts once at the end.

One-Hot Encoding
----------------
A vote for candidate *i* out of *n* candidates is encoded as::

    [0, 0, ..., 1, ..., 0]   (1 at position i, 0 elsewhere)

Homomorphic addition of one-hot vectors gives the per-candidate tally
directly — no intermediate decryption is needed.

Security Parameters (BFV)
--------------------------
* poly_modulus_degree = 4096  (128-bit classical / 64-bit quantum security)
* plain_modulus = 1 032 193   (prime, satisfies BFV constraints)

For production increase to poly_modulus_degree ≥ 8192.
"""

from __future__ import annotations

from typing import Dict, List, Optional

import tenseal as ts

from .config import FHE_PLAIN_MODULUS, FHE_POLY_MOD_DEGREE


# ---------------------------------------------------------------------------
# Authority side
# ---------------------------------------------------------------------------

class FHEAuthority:
    """
    Election-authority FHE context holder.

    Generates the BFV context (including the secret key) and exposes a
    *public* context that voters can use for encryption without being
    able to decrypt any ciphertext.
    """

    def __init__(self, num_candidates: int) -> None:
        self.num_candidates = num_candidates

        # Full context with secret key (kept by the authority)
        self._ctx = ts.context(
            ts.SCHEME_TYPE.BFV,
            poly_modulus_degree=FHE_POLY_MOD_DEGREE,
            plain_modulus=FHE_PLAIN_MODULUS,
        )
        self._ctx.generate_galois_keys()
        self._ctx.generate_relin_keys()

        # Serialise full context (secret key included) for later recovery
        self._full_ctx_bytes: bytes = self._ctx.serialize(save_secret_key=True)

        # Serialise *public* context (no secret key) for voters
        ctx_pub = ts.context_from(self._full_ctx_bytes)
        ctx_pub.make_context_public()
        self._pub_ctx_bytes: bytes = ctx_pub.serialize()

    # ------------------------------------------------------------------
    # Context export
    # ------------------------------------------------------------------

    def public_context_bytes(self) -> bytes:
        """Return the serialised public BFV context (shareable with voters)."""
        return self._pub_ctx_bytes

    def full_context_bytes(self) -> bytes:
        """Return the serialised full context including the secret key."""
        return self._full_ctx_bytes

    # ------------------------------------------------------------------
    # Decryption (authority-only operations)
    # ------------------------------------------------------------------

    def decrypt_tally(self, encrypted_tally_bytes: bytes) -> List[int]:
        """
        Decrypt the homomorphically accumulated tally vector.

        Parameters
        ----------
        encrypted_tally_bytes : Serialised BFV vector (output of FHETally).

        Returns
        -------
        List of vote counts per candidate (position 0 = candidate 0, …).
        """
        ctx      = ts.context_from(self._full_ctx_bytes)
        enc_vec  = ts.bfv_vector_from(ctx, encrypted_tally_bytes)
        plaintext = enc_vec.decrypt()
        return [int(plaintext[i]) for i in range(self.num_candidates)]

    def decrypt_single_vote(self, encrypted_vote_bytes: bytes) -> int:
        """
        Decrypt a single encrypted vote and return the candidate index.
        Intended for audit / testing purposes only.
        """
        ctx       = ts.context_from(self._full_ctx_bytes)
        enc_vec   = ts.bfv_vector_from(ctx, encrypted_vote_bytes)
        plaintext = enc_vec.decrypt()
        for i in range(self.num_candidates):
            if int(plaintext[i]) == 1:
                return i
        return -1  # malformed ballot


# ---------------------------------------------------------------------------
# Voter side
# ---------------------------------------------------------------------------

class FHEVoter:
    """
    Voter-side FHE interface.

    Uses only the *public* BFV context to encrypt individual votes;
    cannot decrypt any ciphertext.
    """

    def __init__(
        self,
        public_context_bytes: bytes,
        num_candidates: int,
    ) -> None:
        self.num_candidates       = num_candidates
        self._ctx                 = ts.context_from(public_context_bytes)

    def encrypt_vote(self, candidate_idx: int) -> bytes:
        """
        Encrypt a vote as a one-hot BFV vector and return the ciphertext bytes.

        Parameters
        ----------
        candidate_idx : Integer index of the chosen candidate [0, num_candidates).

        Returns
        -------
        Serialised BFV ciphertext (bytes).
        """
        if not 0 <= candidate_idx < self.num_candidates:
            raise ValueError(
                f"Candidate index {candidate_idx} out of range "
                f"[0, {self.num_candidates})."
            )
        one_hot = [0] * self.num_candidates
        one_hot[candidate_idx] = 1

        enc = ts.bfv_vector(self._ctx, one_hot)
        return enc.serialize()


# ---------------------------------------------------------------------------
# Tallier (homomorphic accumulation)
# ---------------------------------------------------------------------------

class FHETally:
    """
    Homomorphic vote accumulator.

    Accepts serialised encrypted vote vectors and adds them together
    using BFV homomorphic addition.  The authority calls :meth:`finalize`
    after the poll closes to decrypt the result.
    """

    def __init__(self, authority: FHEAuthority) -> None:
        self._authority       = authority
        self._ctx             = ts.context_from(authority.full_context_bytes())
        self._tally: Optional[ts.BFVVector] = None
        self._vote_count: int = 0

    def add_encrypted_vote(self, encrypted_vote_bytes: bytes) -> None:
        """
        Homomorphically add one encrypted vote to the running tally.

        Parameters
        ----------
        encrypted_vote_bytes : Output of :meth:`FHEVoter.encrypt_vote`.
        """
        enc = ts.bfv_vector_from(self._ctx, encrypted_vote_bytes)
        if self._tally is None:
            self._tally = enc
        else:
            self._tally = self._tally + enc
        self._vote_count += 1

    def encrypted_tally_bytes(self) -> Optional[bytes]:
        """Return the current accumulated encrypted tally, or None if empty."""
        return self._tally.serialize() if self._tally is not None else None

    def finalize(self) -> Dict:
        """
        Decrypt the final tally and return a results dict.

        Returns
        -------
        dict with keys:
            per_candidate – {candidate_index: vote_count, …}
            total_votes   – total number of votes tallied
        """
        if self._tally is None:
            return {
                "per_candidate": {
                    i: 0 for i in range(self._authority.num_candidates)
                },
                "total_votes": 0,
            }

        counts = self._authority.decrypt_tally(self._tally.serialize())
        return {
            "per_candidate": {i: counts[i] for i in range(len(counts))},
            "total_votes":   self._vote_count,
        }

    @property
    def vote_count(self) -> int:
        return self._vote_count
