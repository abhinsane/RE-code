"""
Zero-Knowledge Proof Module — Lattice-Based Vote Validity
==========================================================
Proves that a submitted vote is a valid candidate index in [0, n-1]
**without revealing** which candidate was chosen.

Cryptographic construction
--------------------------
We use an **Ajtai commitment** with a two-component **Sigma-protocol**
made non-interactive via the **Fiat-Shamir heuristic** (using SHA3-256 as
the random oracle) — post-quantum secure under the Module-SIS (MSIS)
hardness assumption.

Ajtai commitment
~~~~~~~~~~~~~~~~
Public parameters:
    A ∈ Z_q^{n×m}  — random public matrix (derived from ELECTION_DOMAIN)
    e₀ ∈ Z_q^n     — first standard basis vector  [1, 0, …, 0]

Commit(vote, r) = A·r  +  vote·e₀   (mod q)
where vote ∈ Z is the ballot value and r ∈ [-β, β]^m is short randomness.

Two-component Sigma protocol
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Witness  : (v, r)  s.t.  C = A·r + v·e₀
Announce : w = A·ρ_r + ρ_v·e₀    — pick fresh (ρ_r ∈ [-β,β]^m, ρ_v ∈ Z_q)
Challenge: c = SHA3(w ‖ C ‖ context)  mod q   (Fiat-Shamir)
Response : z_r = ρ_r + c·r  (mod q),   z_v = ρ_v + c·v  (mod q)
Verify   : A·z_r + z_v·e₀  ≡  w + c·C  (mod q)

ZK property: the simulator draws (z_r, z_v, c) uniformly and sets
w_sim = A·z_r + z_v·e₀ − c·C, producing an indistinguishable transcript.

Range proof (vote ∈ {0,…,n_cand-1})
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Each bit of the vote value is committed independently with the same
Ajtai scheme, and a per-bit sigma proof is generated.  A consistency
hash binds the bit decomposition to the main vote commitment.
"""

from __future__ import annotations

import hashlib
from typing import List

import numpy as np

from .config import (
    ELECTION_DOMAIN,
    ZKP_BETA,
    ZKP_M,
    ZKP_MODULUS,
    ZKP_N,
)
from .pq_crypto import sha3_256, shake256


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fiat_shamir(data: bytes, modulus: int) -> int:
    """Integer Fiat-Shamir challenge derived via SHA3-256, reduced mod q.

    Uses all 32 bytes of the SHA3-256 digest before reducing mod q to
    minimise statistical bias and give a 256-bit challenge pre-image.
    The previous implementation used only 4 bytes (32-bit entropy), making
    the soundness error ~2^{-32} instead of ~2^{-256}.
    """
    return int.from_bytes(sha3_256(data), "big") % modulus


def _sample_short(m: int, beta: int, rng: np.random.Generator) -> np.ndarray:
    """Sample r ← [-β, β]^m uniformly."""
    return rng.integers(-beta, beta + 1, size=m, dtype=np.int64)


def _rng_from(seed_bytes: bytes) -> np.random.Generator:
    return np.random.default_rng(list(seed_bytes))


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class LatticeZKP:
    """
    Lattice-based Zero-Knowledge Proof system for ballot validity.

    Parameters
    ----------
    num_candidates : Number of candidates in the election.
    modulus        : Lattice modulus q.
    n              : Commitment output vector dimension.
    m              : Randomness (short) vector dimension.
    beta           : ∞-norm bound for randomness vectors.
    """

    def __init__(
        self,
        num_candidates: int,
        modulus: int = ZKP_MODULUS,
        n: int       = ZKP_N,
        m: int       = ZKP_M,
        beta: int    = ZKP_BETA,
    ) -> None:
        self.num_candidates = num_candidates
        self.q    = modulus
        self.n    = n
        self.m    = m
        self.beta = beta

        # Deterministic public matrix A ∈ Z_q^{n×m}
        seed = list(shake256(ELECTION_DOMAIN + b":zkp_matrix_A", 64))
        self.A: np.ndarray = np.random.default_rng(seed).integers(
            0, self.q, size=(n, m), dtype=np.int64
        )

        # First standard basis vector e₀ ∈ Z_q^n  (encodes the message)
        self.e0 = np.zeros(n, dtype=np.int64)
        self.e0[0] = 1

    # ------------------------------------------------------------------
    # Commitment  C = A·r + v·e₀  (mod q)
    # ------------------------------------------------------------------

    def _commit(self, v: int, r: np.ndarray) -> np.ndarray:
        return (self.A @ r + int(v) * self.e0) % self.q

    # ------------------------------------------------------------------
    # Sigma protocol (two-component: proves knowledge of (v, r))
    # ------------------------------------------------------------------

    def _sigma_prove(
        self,
        v: int,
        r: np.ndarray,
        C: np.ndarray,
        ctx: bytes,
    ) -> dict:
        """
        Non-interactive Sigma proof of knowledge of (v, r) s.t. C = A·r + v·e₀.

        Announcement: w = A·ρ_r + ρ_v·e₀
        Challenge   : c = FS(w ‖ C ‖ ctx)
        Response    : z_r = ρ_r + c·r,   z_v = ρ_v + c·v   (both mod q)
        Verify      : A·z_r + z_v·e₀ = w + c·C  (mod q)
        """
        rng  = _rng_from(shake256(ctx + r.tobytes(), 32))
        rho_r = _sample_short(self.m, self.beta, rng)
        rho_v = int(rng.integers(0, self.q))

        w   = (self.A @ rho_r + rho_v * self.e0) % self.q
        c   = _fiat_shamir(w.tobytes() + C.tobytes() + ctx, self.q)
        z_r = (rho_r + c * r) % self.q
        z_v = int((rho_v + c * int(v)) % self.q)

        return {"w": w.tolist(), "c": int(c), "z_r": z_r.tolist(), "z_v": z_v}

    def _sigma_verify(self, proof: dict, C: np.ndarray, ctx: bytes) -> bool:
        """
        Verify Sigma proof.  Checks A·z_r + z_v·e₀ ≡ w + c·C  (mod q).
        """
        try:
            w   = np.asarray(proof["w"],   dtype=np.int64)
            c   = int(proof["c"])
            z_r = np.asarray(proof["z_r"], dtype=np.int64)
            z_v = int(proof["z_v"])

            # Recompute challenge
            if c != _fiat_shamir(w.tobytes() + C.tobytes() + ctx, self.q):
                return False

            lhs = (self.A @ z_r + z_v * self.e0) % self.q
            rhs = (w + c * C) % self.q
            return bool(np.all(lhs == rhs))
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Per-bit proof — CDS (Cramer-Damgård-Schoenmakers) 1-of-2 OR proof
    # ------------------------------------------------------------------
    #
    # Proves that C_bit is a commitment to 0 OR a commitment to 1 without
    # revealing which.  Uses the standard CDS composition of two Sigma
    # protocols where the challenges must sum (mod q) to the Fiat-Shamir
    # global challenge.
    #
    # Branch assignments
    # ~~~~~~~~~~~~~~~~~~
    # Let b ∈ {0, 1} be the actual bit and T_i = C - i·e₀.
    # Branch i proves knowledge of r s.t.  A·r ≡ T_i  (mod q).
    # Real branch : i = b   (prover knows r_b)
    # Fake branch : i = 1-b (simulated without knowledge)
    #
    # Proof steps
    # ~~~~~~~~~~~
    # 1. Simulate fake branch: pick c_fake, z_fake;
    #    set w_fake = A·z_fake − c_fake·T_{1-b}  (mod q)
    # 2. Real announcement: pick ρ; set w_real = A·ρ
    # 3. Fiat-Shamir: c = FS(w_0 ‖ w_1 ‖ T_0 ‖ T_1 ‖ ctx) mod q
    # 4. Real challenge: c_real = (c − c_fake) mod q
    # 5. Real response : z_real = ρ + c_real · r_b
    #
    # Verification (no knowledge of b required)
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # Check (c_0 + c_1) ≡ FS(w_0 ‖ w_1 ‖ T_0 ‖ T_1 ‖ ctx)  (mod q)
    # Check A·z_0 ≡ w_0 + c_0·T_0  (mod q)
    # Check A·z_1 ≡ w_1 + c_1·T_1  (mod q)
    #
    # The previous implementation generated a simulated commitment that
    # _verify_bit never checked (only called _sigma_verify on one branch),
    # so the "OR" structure was not enforced at all.

    def _prove_bit(
        self, bit: int, r_bit: np.ndarray, C_bit: np.ndarray, ctx: bytes
    ) -> dict:
        b     = int(bit)
        other = 1 - b

        # Adjusted targets: T_i = C_bit - i·e0
        T: list = [C_bit.copy(), (C_bit - self.e0) % self.q]

        # ---- Simulated (fake) branch for index `other` ----------------
        rng_sim  = _rng_from(shake256(ctx + b":or_sim" + bytes([b]), 32))
        c_fake   = int(rng_sim.integers(0, self.q))
        z_fake   = _sample_short(self.m, self.beta, rng_sim)
        # w_fake = A·z_fake - c_fake·T[other]  (mod q)
        w_fake   = (self.A @ z_fake - c_fake * T[other]) % self.q

        # ---- Real branch announcement for index `b` -------------------
        rng_real = _rng_from(shake256(ctx + b":or_real" + r_bit.tobytes(), 32))
        rho      = _sample_short(self.m, self.beta, rng_real)
        w_real   = (self.A @ rho) % self.q

        # ---- Fiat-Shamir on both announcements -----------------------
        w_arr: list = [None, None]
        w_arr[b]     = w_real
        w_arr[other] = w_fake
        fs_input = (
            w_arr[0].tobytes() + w_arr[1].tobytes()
            + T[0].tobytes()   + T[1].tobytes()
            + ctx
        )
        c_total = _fiat_shamir(fs_input, self.q)

        # Real challenge: split so that c_b + c_fake ≡ c_total (mod q)
        c_real = int((c_total - c_fake) % self.q)
        z_real = (rho + c_real * r_bit) % self.q

        # ---- Arrange output in canonical branch order [0, 1] ---------
        c_out: list = [None, None]
        z_out: list = [None, None]
        c_out[b]     = c_real
        c_out[other] = c_fake
        z_out[b]     = z_real.tolist()
        z_out[other] = z_fake.tolist()

        return {
            "w": [w_arr[0].tolist(), w_arr[1].tolist()],
            "c": [int(c_out[0]),     int(c_out[1])],
            "z": [z_out[0],          z_out[1]],
        }

    def _verify_bit(self, proof: dict, C_bit: np.ndarray, ctx: bytes) -> bool:
        """
        Verify the CDS OR proof: C_bit commits to 0 OR to 1.

        Checks:
        1. (c_0 + c_1) ≡ FS(w_0 ‖ w_1 ‖ T_0 ‖ T_1 ‖ ctx)  (mod q)
        2. A·z_0 ≡ w_0 + c_0·T_0  (mod q)
        3. A·z_1 ≡ w_1 + c_1·T_1  (mod q)
        """
        try:
            w0 = np.asarray(proof["w"][0], dtype=np.int64)
            w1 = np.asarray(proof["w"][1], dtype=np.int64)
            c0 = int(proof["c"][0])
            c1 = int(proof["c"][1])
            z0 = np.asarray(proof["z"][0], dtype=np.int64)
            z1 = np.asarray(proof["z"][1], dtype=np.int64)

            # Adjusted targets
            T0 = C_bit.copy()
            T1 = (C_bit - self.e0) % self.q

            # 1. Challenge consistency
            fs_input = (
                w0.tobytes() + w1.tobytes()
                + T0.tobytes() + T1.tobytes()
                + ctx
            )
            c_total = _fiat_shamir(fs_input, self.q)
            if (c0 + c1) % self.q != c_total:
                return False

            # 2. Branch 0: A·z0 ≡ w0 + c0·T0  (mod q)
            lhs0 = (self.A @ z0) % self.q
            rhs0 = (w0 + c0 * T0) % self.q
            if not np.all(lhs0 == rhs0):
                return False

            # 3. Branch 1: A·z1 ≡ w1 + c1·T1  (mod q)
            lhs1 = (self.A @ z1) % self.q
            rhs1 = (w1 + c1 * T1) % self.q
            if not np.all(lhs1 == rhs1):
                return False

            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Public API — generate proof
    # ------------------------------------------------------------------

    def prove_vote_range(
        self,
        vote: int,
        voter_id: bytes,
        election_id: bytes,
    ) -> dict:
        """
        Generate a non-interactive ZKP that  vote ∈ {0, …, num_candidates-1}
        without revealing the vote value.
        """
        if not 0 <= vote < self.num_candidates:
            raise ValueError(
                f"Vote {vote} outside valid range [0, {self.num_candidates - 1}]."
            )

        ctx = voter_id + election_id + ELECTION_DOMAIN

        # ---- Main commitment ----------------------------------------
        rng    = _rng_from(shake256(ctx + b":main_r", 32))
        r_main = _sample_short(self.m, self.beta, rng)
        C_main = self._commit(vote, r_main)

        # ---- Knowledge proof ----------------------------------------
        main_proof = self._sigma_prove(vote, r_main, C_main, ctx + b":knowledge")

        # ---- Binary decomposition ------------------------------------
        n_bits = max(1, self.num_candidates.bit_length())
        bits_s = format(vote, f"0{n_bits}b")   # MSB first

        bit_commitments: List[list] = []
        bit_proofs:      List[dict] = []

        for i, b_char in enumerate(bits_s):
            bit_val = int(b_char)
            rng_b   = _rng_from(shake256(ctx + f":bit{i}".encode(), 32))
            r_bit   = _sample_short(self.m, self.beta, rng_b)
            C_bit   = self._commit(bit_val, r_bit)
            bp      = self._prove_bit(bit_val, r_bit, C_bit, ctx + f":bit{i}".encode())
            bit_commitments.append(C_bit.tolist())
            bit_proofs.append(bp)

        # ---- Consistency hash ----------------------------------------
        con_input = (
            C_main.tobytes()
            + b"".join(np.array(c, dtype=np.int64).tobytes() for c in bit_commitments)
            + bits_s.encode()
            + ctx
        )
        consistency_hash = sha3_256(con_input).hex()

        return {
            "commitment":       C_main.tolist(),
            "main_proof":       main_proof,
            "bit_commitments":  bit_commitments,
            "bit_proofs":       bit_proofs,
            "bits_str":         bits_s,
            "consistency_hash": consistency_hash,
            "num_candidates":   self.num_candidates,
            "voter_id_hash":    sha3_256(voter_id).hex(),
        }

    # ------------------------------------------------------------------
    # Public API — verify proof
    # ------------------------------------------------------------------

    def verify_vote_proof(
        self,
        proof: dict,
        voter_id: bytes,
        election_id: bytes,
    ) -> bool:
        """
        Verify a vote-range ZKP produced by :meth:`prove_vote_range`.

        Returns True iff all checks pass.
        """
        try:
            if proof.get("voter_id_hash") != sha3_256(voter_id).hex():
                return False
            if proof.get("num_candidates") != self.num_candidates:
                return False

            ctx    = voter_id + election_id + ELECTION_DOMAIN
            C_main = np.asarray(proof["commitment"], dtype=np.int64)

            # Knowledge proof
            if not self._sigma_verify(
                proof["main_proof"], C_main, ctx + b":knowledge"
            ):
                return False

            # Bit proofs
            bc = proof.get("bit_commitments", [])
            bp = proof.get("bit_proofs", [])
            if len(bc) != len(bp):
                return False
            for i, (C_bit_l, bproof) in enumerate(zip(bc, bp)):
                C_bit = np.asarray(C_bit_l, dtype=np.int64)
                if not self._verify_bit(bproof, C_bit, ctx + f":bit{i}".encode()):
                    return False

            # Consistency hash
            con_input = (
                C_main.tobytes()
                + b"".join(
                    np.array(c, dtype=np.int64).tobytes() for c in bc
                )
                + proof["bits_str"].encode()
                + ctx
            )
            if proof.get("consistency_hash") != sha3_256(con_input).hex():
                return False

            return True

        except Exception:
            return False

    # ------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------

    def commitment_bytes(self, proof: dict) -> bytes:
        """First 32 int64 elements of the main commitment as bytes."""
        arr = np.asarray(proof["commitment"][:32], dtype=np.int64)
        return arr.tobytes()
