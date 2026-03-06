"""
Post-Quantum Cryptography Module
=================================
Provides hybrid (KEM + symmetric) encryption and lattice-based digital
signatures that are secure against both classical and quantum adversaries.

Algorithms
----------
* ML-KEM-768  (NIST FIPS 203) – Key Encapsulation Mechanism
  Wraps AES-256-GCM symmetric keys; replaces RSA/ECDH key exchange.
* ML-DSA-65   (NIST FIPS 204) – Module-Lattice Digital Signature Algorithm
  Replaces RSA/ECDSA signatures; used for votes, blocks, and results.
* AES-256-GCM – Authenticated symmetric encryption (NIST SP 800-38D).
* SHA3-256 / SHAKE256 – Quantum-safe hashing and key derivation.

All biometric templates, votes, and keys are wrapped with this layer.
"""

from __future__ import annotations

import os
import hashlib
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# NIST-standardised post-quantum primitives (pqcrypto package)
from pqcrypto.kem.ml_kem_768 import (
    generate_keypair as _kem_keygen,
    encrypt        as _kem_enc,
    decrypt        as _kem_dec,
)
from pqcrypto.sign.ml_dsa_65 import (
    generate_keypair as _sig_keygen,
    sign             as _sig_sign,
    verify           as _sig_verify,
)

from .config import SYM_KEY_SIZE, SYM_NONCE_SIZE

# ---------------------------------------------------------------------------
# Hash helpers
# ---------------------------------------------------------------------------

def sha3_256(data: bytes) -> bytes:
    """SHA3-256 — quantum-safe collision-resistant hash."""
    return hashlib.sha3_256(data).digest()


def shake256(data: bytes, length: int = 32) -> bytes:
    """SHAKE256 XOF — variable-length quantum-safe output."""
    return hashlib.shake_256(data).digest(length)


# ---------------------------------------------------------------------------
# PQ Key-pair container
# ---------------------------------------------------------------------------

class PQKeyPair:
    """
    A holder for a voter's or authority's post-quantum key material.

    Attributes
    ----------
    kem_pk / kem_sk  : ML-KEM-768 public / secret key bytes
    sig_pk / sig_sk  : ML-DSA-65  public / secret key bytes
    """

    def __init__(self) -> None:
        """Generate a fresh PQ key pair."""
        self.kem_pk, self.kem_sk = _kem_keygen()
        self.sig_pk, self.sig_sk = _sig_keygen()

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    def public_dict(self) -> dict:
        """Return only the public keys (safe to share)."""
        return {
            "kem_pk": self.kem_pk.hex(),
            "sig_pk": self.sig_pk.hex(),
        }

    def full_dict(self) -> dict:
        """Return full key material (keep confidential)."""
        return {
            "kem_pk": self.kem_pk.hex(),
            "kem_sk": self.kem_sk.hex(),
            "sig_pk": self.sig_pk.hex(),
            "sig_sk": self.sig_sk.hex(),
        }


# ---------------------------------------------------------------------------
# Hybrid encryption  (ML-KEM-768 + AES-256-GCM)
# ---------------------------------------------------------------------------

def pq_encrypt(recipient_kem_pk: bytes, plaintext: bytes) -> dict:
    """
    Hybrid-encrypt *plaintext* for *recipient_kem_pk*.

    1. Encapsulate a fresh shared-secret with ML-KEM-768.
    2. Derive a 256-bit AES key via SHAKE256(shared_secret ‖ "aes256gcm").
    3. Encrypt *plaintext* with AES-256-GCM (authenticated).

    Returns
    -------
    dict with keys:
        kem_ct   – ML-KEM-768 ciphertext (hex str)
        aes_ct   – AES-GCM ciphertext    (hex str, includes 16-byte tag)
        nonce    – 12-byte GCM nonce     (hex str)
    """
    # Step 1 – ML-KEM encapsulation
    kem_ct, shared_secret = _kem_enc(recipient_kem_pk)

    # Step 2 – Key derivation
    aes_key = shake256(shared_secret + b"aes256gcm_key_derivation", SYM_KEY_SIZE)

    # Step 3 – AES-256-GCM encryption
    nonce = os.urandom(SYM_NONCE_SIZE)
    aes_ct = AESGCM(aes_key).encrypt(nonce, plaintext, None)

    return {
        "kem_ct": kem_ct.hex(),
        "aes_ct": aes_ct.hex(),
        "nonce":  nonce.hex(),
    }


def pq_decrypt(kem_sk: bytes, envelope: dict) -> bytes:
    """
    Hybrid-decrypt an envelope produced by :func:`pq_encrypt`.

    Parameters
    ----------
    kem_sk   : recipient's ML-KEM-768 secret key bytes
    envelope : dict returned by pq_encrypt (hex strings or raw bytes accepted)
    """
    # Normalise – accept both hex strings and raw bytes for each field
    def _to_bytes(v):
        return bytes.fromhex(v) if isinstance(v, str) else v

    kem_ct = _to_bytes(envelope["kem_ct"])
    aes_ct = _to_bytes(envelope["aes_ct"])
    nonce  = _to_bytes(envelope["nonce"])

    # Step 1 – ML-KEM decapsulation
    shared_secret = _kem_dec(kem_sk, kem_ct)

    # Step 2 – Key derivation (must match encryption)
    aes_key = shake256(shared_secret + b"aes256gcm_key_derivation", SYM_KEY_SIZE)

    # Step 3 – AES-256-GCM decryption + authentication
    return AESGCM(aes_key).decrypt(nonce, aes_ct, None)


# ---------------------------------------------------------------------------
# Digital signatures  (ML-DSA-65)
# ---------------------------------------------------------------------------

def pq_sign(sig_sk: bytes, message: bytes) -> bytes:
    """Sign *message* with *sig_sk* using ML-DSA-65."""
    return _sig_sign(sig_sk, message)


def pq_verify(sig_pk: bytes, message: bytes, signature: bytes) -> bool:
    """
    Verify *signature* over *message* with *sig_pk* (ML-DSA-65).
    Returns True iff valid; never raises.
    """
    try:
        return bool(_sig_verify(sig_pk, message, signature))
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Convenience wrappers
# ---------------------------------------------------------------------------

def pq_hash(data: bytes) -> bytes:
    """Quantum-safe SHA3-256 digest of *data*."""
    return sha3_256(data)
