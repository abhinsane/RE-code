"""
Voter Data Model and Registry
==============================
Defines the :class:`VoterRegistration` record that holds all public
information about a registered voter (no secret keys stored) and the
:class:`VoterRegistry` that manages the roster.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .config import AUTH_SESSION_TIMEOUT
from .pq_crypto import sha3_256


# ---------------------------------------------------------------------------
# Voter registration record
# ---------------------------------------------------------------------------

@dataclass
class VoterRegistration:
    """
    Publicly shareable registration record for a single voter.

    Secret keys are held exclusively by the voter's client and are
    never stored in the registry.

    Fields
    ------
    voter_id          : Randomly generated UUID string.
    voter_id_hash     : SHA3-256(voter_id) — stored on-chain for privacy.
    kem_pk            : ML-KEM-768 public key bytes (for encrypted messages).
    sig_pk            : ML-DSA-65  public key bytes (for signature verification).
    biometric_data    : Dict returned by CancellableBiometric.enroll().
    registered_at     : Unix timestamp of registration.
    is_active         : Whether the voter may cast a vote.
    has_voted         : Set to True once a valid vote is accepted.
    """

    voter_id:      str  = field(default_factory=lambda: str(uuid.uuid4()))
    voter_id_hash: str  = field(default="")
    kem_pk:        bytes = field(default=b"")
    sig_pk:        bytes = field(default=b"")
    biometric_data: dict = field(default_factory=dict)
    registered_at:  float = field(default_factory=time.time)
    is_active:          bool          = True
    has_voted:          bool          = False
    bio_authenticated:  bool          = False   # set to True only after biometric passes
    bio_auth_time:      Optional[float] = None  # unix timestamp of last successful auth

    def __post_init__(self) -> None:
        if not self.voter_id_hash:
            self.voter_id_hash = sha3_256(self.voter_id.encode()).hex()

    def id_bytes(self) -> bytes:
        return self.voter_id.encode()

    def public_record(self) -> dict:
        """Return only the publicly shareable fields."""
        return {
            "voter_id_hash": self.voter_id_hash,
            "sig_pk":        self.sig_pk.hex() if self.sig_pk else "",
            "kem_pk":        self.kem_pk.hex() if self.kem_pk else "",
            "registered_at": self.registered_at,
            "is_active":     self.is_active,
        }


# ---------------------------------------------------------------------------
# Voter registry
# ---------------------------------------------------------------------------

class VoterRegistry:
    """
    In-memory voter registry.

    In a production system this would be backed by a database and access
    would be access-controlled.
    """

    def __init__(self) -> None:
        self._records: Dict[str, VoterRegistration] = {}

    def register(self, reg: VoterRegistration) -> bool:
        """
        Add a voter to the registry.

        Returns False if the voter_id already exists (duplicate).
        """
        if reg.voter_id in self._records:
            return False
        self._records[reg.voter_id] = reg
        return True

    def get(self, voter_id: str) -> Optional[VoterRegistration]:
        return self._records.get(voter_id)

    def mark_authenticated(self, voter_id: str) -> bool:
        """
        Record that a voter passed biometric verification this session.

        Must be called by the authority after a successful authenticate()
        before receive_vote() will accept a ballot from this voter.
        Records the current timestamp so the token can be expired after
        AUTH_SESSION_TIMEOUT seconds.
        """
        reg = self._records.get(voter_id)
        if reg is None or not reg.is_active:
            return False
        reg.bio_authenticated = True
        reg.bio_auth_time     = time.time()
        return True

    def is_authenticated(self, voter_id: str) -> bool:
        """
        Return True iff the voter passed biometric auth this session AND
        the session has not expired (within AUTH_SESSION_TIMEOUT seconds).

        Previously had no expiry: a token set at poll-open would remain valid
        until the voter cast their vote, allowing indefinite time between
        authentication and ballot submission.
        """
        reg = self._records.get(voter_id)
        if not (reg and reg.bio_authenticated and reg.bio_auth_time is not None):
            return False
        elapsed = time.time() - reg.bio_auth_time
        if elapsed > AUTH_SESSION_TIMEOUT:
            # Expire the stale token automatically
            reg.bio_authenticated = False
            reg.bio_auth_time     = None
            return False
        return True

    def clear_authentication(self, voter_id: str) -> None:
        """Clear the biometric auth flag and timestamp (called after vote is cast)."""
        reg = self._records.get(voter_id)
        if reg:
            reg.bio_authenticated = False
            reg.bio_auth_time     = None

    def mark_voted(self, voter_id: str) -> bool:
        """
        Mark a voter as having voted.

        Returns False if the voter does not exist, is inactive, or has
        already voted.
        """
        reg = self._records.get(voter_id)
        if reg is None or not reg.is_active or reg.has_voted:
            return False
        reg.has_voted = True
        return True

    def is_registered(self, voter_id: str) -> bool:
        return voter_id in self._records

    def has_voted(self, voter_id: str) -> bool:
        reg = self._records.get(voter_id)
        return reg.has_voted if reg else False

    def total_registered(self) -> int:
        return len(self._records)

    def total_voted(self) -> int:
        return sum(1 for r in self._records.values() if r.has_voted)

    def all_public_records(self) -> list:
        return [r.public_record() for r in self._records.values()]

    def authenticated_not_voted(self) -> List[str]:
        """
        Return the voter IDs of voters who passed biometric authentication
        in this session but whose ballot was never recorded.

        Used by ElectionAuthority.finalize() to detect and clear dangling
        authentication tokens without accessing the private _records dict.
        Only non-expired tokens are included.
        """
        now = time.time()
        return [
            vid for vid, reg in self._records.items()
            if reg.bio_authenticated
            and reg.bio_auth_time is not None
            and (now - reg.bio_auth_time) <= AUTH_SESSION_TIMEOUT
        ]
