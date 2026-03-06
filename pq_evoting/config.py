"""
Configuration constants for the Post-Quantum E-Voting System.

Cryptographic algorithms used:
  - Key Encapsulation : ML-KEM-768  (NIST FIPS 203 / CRYSTALS-Kyber level 3)
  - Digital Signatures: ML-DSA-65   (NIST FIPS 204 / CRYSTALS-Dilithium level 3)
  - Symmetric cipher  : AES-256-GCM (shared secret from ML-KEM)
  - Hash / XOF        : SHA3-256 / SHAKE256 (quantum-safe)
  - FHE               : BFV scheme  (TenSEAL)
  - ZKP               : Lattice-based Ajtai commitment with Fiat-Shamir
  - Biometrics        : BioHashing on ORB features (SOCOFing dataset)
"""

# ---------------------------------------------------------------------------
# Post-Quantum Key algorithms
# ---------------------------------------------------------------------------
PQ_KEM_ALGORITHM = "ml_kem_768"   # CRYSTALS-Kyber (NIST ML-KEM Level 3)
PQ_SIG_ALGORITHM = "ml_dsa_65"    # CRYSTALS-Dilithium (NIST ML-DSA Level 3)

# ---------------------------------------------------------------------------
# Symmetric encryption
# ---------------------------------------------------------------------------
SYM_KEY_SIZE   = 32   # 256-bit AES-GCM key
SYM_NONCE_SIZE = 12   # 96-bit GCM nonce (recommended)

# ---------------------------------------------------------------------------
# FHE parameters (TenSEAL BFV)
# ---------------------------------------------------------------------------
FHE_POLY_MOD_DEGREE = 4096
FHE_PLAIN_MODULUS   = 1032193   # Must be prime & ≡ 1 (mod 2*poly_mod_degree)

# ---------------------------------------------------------------------------
# ZKP parameters — Lattice-based Ajtai commitment (simplified prototype)
# ---------------------------------------------------------------------------
ZKP_MODULUS = (1 << 23) - 7    # Small safe prime (2^23 - 7) for prototype
ZKP_N       = 64               # Commitment vector dimension
ZKP_M       = 128              # Randomness vector dimension
ZKP_BETA    = 800              # ∞-norm bound for short randomness vectors

# ---------------------------------------------------------------------------
# Cancellable biometric parameters
# ---------------------------------------------------------------------------
BIO_FEATURE_DIM     = 512    # Output dimension after BioHash projection
BIO_KEYPOINTS       = 256    # ORB keypoints to extract per fingerprint
BIO_MATCH_THRESHOLD = 0.80   # Hamming-similarity threshold for accept/reject

# ---------------------------------------------------------------------------
# Blockchain parameters
# ---------------------------------------------------------------------------
BLOCKCHAIN_DIFFICULTY = 2    # PoW leading-zero count (increase for production)

# ---------------------------------------------------------------------------
# Authentication session timeout
# ---------------------------------------------------------------------------
# A biometric authentication token is valid for this many seconds.
# After this window the voter must re-authenticate before casting their vote.
# Without a timeout, an authentication from the start of polling day would
# remain valid indefinitely, even if the voter walked away.
AUTH_SESSION_TIMEOUT = 600   # 10 minutes

# ---------------------------------------------------------------------------
# Biometric brute-force lockout
# ---------------------------------------------------------------------------
# After BIO_MAX_AUTH_ATTEMPTS consecutive failed biometric checks the voter
# account is locked for BIO_LOCKOUT_SECONDS.  The counter resets on any
# successful verification.
BIO_MAX_AUTH_ATTEMPTS = 5     # consecutive failures before lockout
BIO_LOCKOUT_SECONDS   = 300   # 5-minute lockout window

# ---------------------------------------------------------------------------
# Election domain separator (embedded in every hash / ZKP challenge)
# ---------------------------------------------------------------------------
ELECTION_DOMAIN = b"pq_evoting_2024_domain_sep"
