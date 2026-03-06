"""
pq_evoting — Post-Quantum E-Voting System
==========================================
A research prototype combining:

* **ML-KEM-768** (NIST FIPS 203 / CRYSTALS-Kyber) — post-quantum KEM
* **ML-DSA-65**  (NIST FIPS 204 / CRYSTALS-Dilithium) — post-quantum signatures
* **TenSEAL BFV** — Fully Homomorphic Encryption for encrypted vote tallying
* **Lattice-based ZKP** — Ajtai commitment + Fiat-Shamir range proof
* **BioHashing** — Cancellable biometrics on SOCOFing fingerprint dataset
* **SHA3-256 blockchain** — Immutable, ML-DSA-signed vote ledger
"""

from .config import (
    BIO_FEATURE_DIM, BIO_KEYPOINTS, BIO_MATCH_THRESHOLD,
    BLOCKCHAIN_DIFFICULTY, ELECTION_DOMAIN,
    FHE_PLAIN_MODULUS, FHE_POLY_MOD_DEGREE,
    PQ_KEM_ALGORITHM, PQ_SIG_ALGORITHM,
    SYM_KEY_SIZE, SYM_NONCE_SIZE,
    ZKP_BETA, ZKP_M, ZKP_MODULUS, ZKP_N,
)
from .pq_crypto import (
    PQKeyPair,
    pq_decrypt, pq_encrypt, pq_hash, pq_sign, pq_verify,
    sha3_256, shake256,
)
from .cancellable_biometric import (
    CancellableBiometric,
    create_synthetic_fingerprint,
    load_socofing_samples,
)
from .fhe_voting import FHEAuthority, FHETally, FHEVoter
from .zkp import LatticeZKP
from .blockchain import Block, VoteRecord, VotingBlockchain
from .voter import VoterRegistration, VoterRegistry
from .voting_system import ElectionAuthority, ElectionConfig, Voter

__version__  = "1.0.0"
__all__ = [
    # voting_system
    "ElectionAuthority", "ElectionConfig", "Voter",
    # pq_crypto
    "PQKeyPair", "pq_encrypt", "pq_decrypt", "pq_sign", "pq_verify",
    "pq_hash", "sha3_256", "shake256",
    # cancellable_biometric
    "CancellableBiometric", "load_socofing_samples",
    "create_synthetic_fingerprint",
    # fhe_voting
    "FHEAuthority", "FHEVoter", "FHETally",
    # zkp
    "LatticeZKP",
    # blockchain
    "VotingBlockchain", "Block", "VoteRecord",
    # voter
    "VoterRegistration", "VoterRegistry",
]
