"""
Cancellable Biometric Module — SOCOFing Fingerprint Dataset
============================================================
Implements **BioHashing** for fingerprint template protection:

1. **Feature extraction** – ORB keypoints + descriptors from fingerprint image
   (fallback to HOG-style gradient histogram when ORB keypoints are sparse).

2. **BioHash transformation** – The raw feature vector is projected onto a
   user-specific pseudo-random orthogonal subspace derived from a secret
   *user token* (e.g., a hashed PIN).  Only the projected, binarised
   template is stored — not the raw biometric.

3. **PQ-encrypted template storage** – The binarised BioHash template is
   hybrid-encrypted with the election authority's ML-KEM-768 public key
   before storage, ensuring post-quantum confidentiality.

4. **Cancelability** – If a template is compromised, the voter changes their
   PIN / token; a new orthogonal matrix is derived and a fresh template is
   enrolled.  Old templates are revoked and cannot be linked to new ones.

SOCOFing Dataset (Sokoto Coventry Fingerprint Dataset)
------------------------------------------------------
Images are stored as: SOCOFing/Real/{ID}_{Hand}_{Finger}.BMP
e.g. ``1__M_Left_index_finger.BMP``
Subjects 1–600 with up to 10 fingers per subject.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import cv2
import numpy as np

from .config import BIO_FEATURE_DIM, BIO_KEYPOINTS, BIO_MATCH_THRESHOLD
from .pq_crypto import pq_encrypt, pq_decrypt, shake256

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _token_to_seed(user_token: bytes) -> int:
    """Derive a 64-bit integer RNG seed from the user token via SHAKE256."""
    seed_bytes = shake256(b"biohash_rng_seed" + user_token, 8)
    return int.from_bytes(seed_bytes, "big") % (2**32)


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class CancellableBiometric:
    """
    Cancellable biometric processor for SOCOFing fingerprint images.

    Parameters
    ----------
    feature_dim : int
        Output dimension of the BioHash (number of projected bits).
    num_keypoints : int
        Number of ORB keypoints to extract per image.
    """

    # ORB descriptor width is always 32 bytes = 256 bits
    _DESC_BYTES: int = 32

    def __init__(
        self,
        feature_dim: int  = BIO_FEATURE_DIM,
        num_keypoints: int = BIO_KEYPOINTS,
    ) -> None:
        self.feature_dim   = feature_dim
        self.num_keypoints = num_keypoints
        self._raw_dim      = num_keypoints * self._DESC_BYTES  # flat ORB vector
        self._orb          = cv2.ORB_create(nfeatures=num_keypoints)

    # ------------------------------------------------------------------
    # Feature extraction
    # ------------------------------------------------------------------

    def extract_features(self, image_path: str) -> np.ndarray:
        """
        Extract a normalised, fixed-size float32 feature vector from a
        fingerprint image.

        Steps
        -----
        1. Load as grayscale and resize to 96×96.
        2. Apply CLAHE for contrast enhancement.
        3. Extract up to *num_keypoints* ORB keypoints; fall back to HOG
           gradient histogram if keypoint count is too low.
        4. Flatten, pad/truncate to *_raw_dim*, and L2-normalise.
        """
        img = cv2.imread(str(image_path), cv2.IMREAD_GRAYSCALE)
        if img is None:
            raise ValueError(f"Cannot load fingerprint image: {image_path}")

        img = cv2.resize(img, (96, 96))
        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        img   = clahe.apply(img)

        keypoints, descriptors = self._orb.detectAndCompute(img, None)

        if descriptors is not None and len(descriptors) >= 8:
            desc = descriptors.astype(np.float32)
            # Pad / truncate to num_keypoints rows
            if len(desc) < self.num_keypoints:
                pad  = np.zeros(
                    (self.num_keypoints - len(desc), self._DESC_BYTES),
                    dtype=np.float32,
                )
                desc = np.vstack([desc, pad])
            else:
                desc = desc[: self.num_keypoints]
            feature = desc.flatten()
        else:
            feature = self._hog_fallback(img)

        norm = np.linalg.norm(feature)
        return feature / norm if norm > 1e-9 else feature

    def _hog_fallback(self, img: np.ndarray) -> np.ndarray:
        """HOG-style gradient histogram (fallback when ORB yields <8 kps)."""
        gx  = cv2.Sobel(img, cv2.CV_32F, 1, 0, ksize=3)
        gy  = cv2.Sobel(img, cv2.CV_32F, 0, 1, ksize=3)
        _, angle = cv2.cartToPolar(gx, gy, angleInDegrees=True)
        bins = self.num_keypoints * self._DESC_BYTES
        hist, _ = np.histogram(angle.flatten(), bins=bins, range=(0.0, 360.0))
        feature = hist.astype(np.float32)
        norm    = np.linalg.norm(feature)
        return feature / norm if norm > 1e-9 else feature

    # ------------------------------------------------------------------
    # BioHashing
    # ------------------------------------------------------------------

    def _projection_matrix(self, user_token: bytes) -> np.ndarray:
        """
        Build a pseudo-random orthogonal projection matrix of shape
        (feature_dim × raw_dim).

        Method
        ------
        1. Seed a NumPy RNG with SHAKE256(token).
        2. Fill a (feature_dim × raw_dim) matrix with standard-normal entries.
        3. QR-decompose to obtain an orthonormal set of row vectors.
        """
        seed = _token_to_seed(user_token)
        rng  = np.random.default_rng(seed)
        M    = rng.standard_normal((self._raw_dim, self.feature_dim))
        Q, _ = np.linalg.qr(M)          # Q is (raw_dim × feature_dim)
        return Q.T                       # (feature_dim × raw_dim)

    def compute_biohash(
        self, feature: np.ndarray, user_token: bytes
    ) -> np.ndarray:
        """
        Apply BioHash: project *feature* onto the user-specific orthogonal
        subspace, then binarise at the median.

        Returns
        -------
        np.ndarray of dtype uint8, shape (feature_dim,), values in {0, 1}.
        """
        P = self._projection_matrix(user_token)

        # Align feature length with expected raw_dim
        f = np.asarray(feature, dtype=np.float32)
        if len(f) < self._raw_dim:
            f = np.pad(f, (0, self._raw_dim - len(f)))
        else:
            f = f[: self._raw_dim]

        projected = P @ f
        return (projected > np.median(projected)).astype(np.uint8)

    # ------------------------------------------------------------------
    # Enrolment
    # ------------------------------------------------------------------

    def enroll(
        self,
        image_path: str,
        user_token: bytes,
        authority_kem_pk: bytes,
    ) -> dict:
        """
        Enrol a voter: extract biometric features, compute the cancellable
        BioHash template, and PQ-encrypt it for secure storage.

        Parameters
        ----------
        image_path      : Path to a SOCOFing fingerprint image.
        user_token      : Secret token (e.g. SHA3-256 of PIN) known only to
                          the voter.  Changing this token cancels the template.
        authority_kem_pk: Election authority's ML-KEM-768 public key used to
                          encrypt the template.

        Returns
        -------
        dict with keys:
            encrypted_template – PQ-encrypted BioHash bytes (dict)
            template_hash      – SHA3-256 of raw BioHash template (hex)
            token_hash         – SHA3-256 of user_token (hex) — stored for
                                 lightweight token validation
            feature_dim        – int
        """
        feature  = self.extract_features(image_path)
        biohash  = self.compute_biohash(feature, user_token)
        raw_tmpl = biohash.tobytes()

        encrypted_template = pq_encrypt(authority_kem_pk, raw_tmpl)

        return {
            "encrypted_template": encrypted_template,
            "template_hash":      hashlib.sha3_256(raw_tmpl).hexdigest(),
            "token_hash":         hashlib.sha3_256(user_token).hexdigest(),
            "feature_dim":        self.feature_dim,
        }

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(
        self,
        image_path: str,
        user_token: bytes,
        authority_kem_sk: bytes,
        enrolled: dict,
    ) -> Tuple[bool, float]:
        """
        Verify a voter's live fingerprint against their enrolled template.

        Steps
        -----
        1. Validate the token hash (cheap check before biometric comparison).
        2. Decrypt the stored BioHash template using the authority's secret key.
        3. Compute BioHash of the live fingerprint.
        4. Compute fractional Hamming similarity; accept if ≥ threshold.

        Returns
        -------
        (is_match: bool, similarity_score: float)
        """
        # Token check
        if hashlib.sha3_256(user_token).hexdigest() != enrolled["token_hash"]:
            return False, 0.0

        # Decrypt stored template
        raw_tmpl = pq_decrypt(authority_kem_sk, enrolled["encrypted_template"])
        stored   = np.frombuffer(raw_tmpl, dtype=np.uint8)

        # Extract live BioHash
        feature = self.extract_features(image_path)
        query   = self.compute_biohash(feature, user_token)

        # Align lengths
        n       = min(len(stored), len(query))
        stored  = stored[:n]
        query   = query[:n]

        hamming_dist  = int(np.sum(stored != query))
        similarity    = 1.0 - hamming_dist / n

        return similarity >= BIO_MATCH_THRESHOLD, float(similarity)

    # ------------------------------------------------------------------
    # Template cancellation
    # ------------------------------------------------------------------

    def cancel_and_reenroll(
        self,
        image_path: str,
        old_token: bytes,
        new_token: bytes,
        authority_kem_pk: bytes,
        authority_kem_sk: bytes,
        enrolled: dict,
    ) -> dict:
        """
        Revoke a compromised template and create a fresh one with *new_token*.

        The old token is verified first; if it does not match the live
        fingerprint the cancellation is rejected (prevents attacker abuse).

        Returns
        -------
        A new *enrolled* dict that replaces the old one.
        """
        is_match, score = self.verify(
            image_path, old_token, authority_kem_sk, enrolled
        )
        if not is_match:
            raise ValueError(
                f"Old-token verification failed (score={score:.3f}).  "
                "Cannot cancel template."
            )
        return self.enroll(image_path, new_token, authority_kem_pk)


# ---------------------------------------------------------------------------
# Dataset loader
# ---------------------------------------------------------------------------

def load_socofing_samples(
    dataset_path: str,
    num_subjects: int = 10,
    min_samples_per_subject: int = 2,
) -> Dict[str, List[str]]:
    """
    Discover and group SOCOFing fingerprint images by subject ID.

    SOCOFing naming convention (Real folder)::

        {subject_id}__{gender}_{hand}_{finger}_finger.BMP
        e.g.  ``1__M_Left_index_finger.BMP``

    Parameters
    ----------
    dataset_path             : Root of the SOCOFing directory (contains Real/).
    num_subjects             : Maximum number of subjects to load.
    min_samples_per_subject  : Skip subjects with fewer than this many images.

    Returns
    -------
    Dict mapping subject_id (str) → list of absolute image paths (str).

    Raises
    ------
    FileNotFoundError if no images are found.
    """
    root      = Path(dataset_path)
    real_dir  = root / "Real"
    search_in = real_dir if real_dir.exists() else root

    extensions = ["*.BMP", "*.bmp", "*.png", "*.PNG", "*.jpg", "*.JPG"]
    image_files: List[Path] = []
    for ext in extensions:
        image_files.extend(search_in.glob(ext))

    if not image_files:
        raise FileNotFoundError(
            f"No fingerprint images found under '{search_in}'.  "
            "Please extract the SOCOFing dataset there."
        )

    samples: Dict[str, List[str]] = {}
    for img_path in sorted(image_files):
        # Subject ID is the first token before '__' or '_'
        stem  = img_path.stem
        parts = stem.split("__")
        subj  = parts[0] if len(parts) > 1 else stem.split("_")[0]

        samples.setdefault(subj, []).append(str(img_path))
        if len(samples) >= num_subjects * 3:
            break  # over-collect then prune below

    # Prune to subjects with enough samples
    valid = {
        s: p for s, p in samples.items()
        if len(p) >= min_samples_per_subject
    }

    if not valid:
        # Fall back: return whatever we have
        valid = {s: p for s, p in samples.items() if p}

    return dict(list(valid.items())[:num_subjects])


def create_synthetic_fingerprint(
    path: str,
    seed: int = 42,
    size: Tuple[int, int] = (96, 96),
) -> None:
    """
    Generate a synthetic ridge-like fingerprint image for testing when
    the SOCOFing dataset is not available locally.
    """
    rng = np.random.default_rng(seed)
    h, w = size
    img  = np.zeros((h, w), dtype=np.uint8)

    # Concentric elliptic ridges mimicking a fingerprint
    cy, cx = h // 2, w // 2
    for r in range(5, min(h, w) // 2, 7):
        # Add noise to ridge position
        for angle in np.linspace(0, 2 * np.pi, 200):
            noise = rng.integers(-2, 3)
            y = int(cy + (r + noise) * np.sin(angle))
            x = int(cx + (r + noise) * np.cos(angle) * 1.2)
            if 0 <= y < h and 0 <= x < w:
                img[y, x] = 200 + rng.integers(0, 56)

    # Smooth to look more natural
    img = cv2.GaussianBlur(img, (3, 3), 1)
    cv2.imwrite(str(path), img)
