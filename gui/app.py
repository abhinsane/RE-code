"""
Post-Quantum E-Voting System — Streamlit Dashboard
====================================================
Five-tab interface:

  🏛️ Setup     — Configure election, deploy Ethereum contract
  📋 Register  — Enrol voters (biometric + PQ keys)
  🗳️ Vote      — Biometric auth + encrypted ballot casting
  📊 Results   — FHE-decrypted tally + Plotly charts
  ⛓️ Chain     — Dual-blockchain explorer (PQ chain + Ethereum)

Run:
  cd /path/to/RE-code
  streamlit run gui/app.py
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional

import plotly.graph_objects as go
import streamlit as st
from streamlit.delta_generator import DeltaGenerator

# ── resolve package paths ────────────────────────────────────────────────────
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from pq_evoting import (
    CancellableBiometric,
    ElectionAuthority,
    ElectionConfig,
    Voter,
    create_synthetic_fingerprint,
    pq_verify,
    sha3_256,
)
from pq_evoting.config import BIO_MATCH_THRESHOLD
from eth_integration import EthBridge

# ── page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title  = "PQ E-Voting",
    page_icon   = "🗳️",
    layout      = "wide",
    initial_sidebar_state = "expanded",
)

# ── Injected CSS ─────────────────────────────────────────────────────────────
st.markdown("""
<style>
  .stTabs [data-baseweb="tab-list"] { gap: 6px; }
  .stTabs [data-baseweb="tab"] {
      padding: 8px 18px; border-radius: 6px 6px 0 0;
      font-weight: 600;
  }
  .metric-box {
      background: #1e2130; border-radius: 8px;
      padding: 14px 18px; margin: 4px 0;
  }
  .vote-receipt {
      background: #0e1117; border: 1px solid #2d3250;
      border-radius: 8px; padding: 16px; font-family: monospace;
      font-size: 12px;
  }
  .chain-block {
      background: #1e2130; border-left: 3px solid #4c8df5;
      border-radius: 4px; padding: 10px 14px; margin: 6px 0;
  }
  .event-row {
      background: #1a1f2e; border-left: 3px solid #f5a623;
      border-radius: 4px; padding: 8px 12px; margin: 4px 0;
      font-family: monospace; font-size: 11px;
  }
  .accepted { color: #4caf50; font-weight: bold; }
  .rejected { color: #f44336; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

# ── Session state init ────────────────────────────────────────────────────────

def _init_state() -> None:
    defaults = {
        "phase":          "setup",       # setup | registration | voting | closed | finalized
        "authority":      None,
        "public_params":  None,
        "eth_bridge":     None,
        "voters":         {},            # voter_id -> Voter
        "voter_tokens":   {},            # voter_id -> bytes
        "voter_fps":      {},            # voter_id -> {"enrol": path, "verify": path}
        "vote_log":       [],            # list of dicts
        "auth_result":    None,         # {"voter_id", "ok", "score"} — cleared after vote
        "results":        None,
        "chain_stats":    {},
        "finalize_tx":    None,
        "tmp_dir":        tempfile.mkdtemp(),
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

_init_state()
S = st.session_state   # shorthand


# ── Helpers ──────────────────────────────────────────────────────────────────

def _token(voter_id: str, pin: str) -> bytes:
    return hashlib.sha3_256(f"{voter_id}:{pin}".encode()).digest()


def _save_upload(uploaded, prefix: str) -> str:
    """Save a Streamlit UploadedFile to a temp path and return the path."""
    suffix = Path(uploaded.name).suffix or ".png"
    path   = os.path.join(S.tmp_dir, f"{prefix}{suffix}")
    with open(path, "wb") as f:
        f.write(uploaded.getbuffer())
    return path


def _synth_fp(voter_id: str, variant: int = 0) -> str:
    """Generate (or reuse) a synthetic fingerprint for a voter."""
    path = os.path.join(S.tmp_dir, f"fp_{voter_id}_{variant}.png")
    if not os.path.exists(path):
        seed = abs(hash(voter_id)) % (2**31) + variant
        create_synthetic_fingerprint(path, seed=seed)
    return path


def _phase_badge() -> str:
    colours = {
        "setup":        "🔵",
        "registration": "🟡",
        "voting":       "🟢",
        "closed":       "🟠",
        "finalized":    "🏁",
    }
    return colours.get(S.phase, "⚪") + f" `{S.phase.upper()}`"


# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.title("🗳️ PQ E-Voting")
    st.caption("Post-Quantum · FHE · ZKP · Biometrics · Blockchain")
    st.divider()

    st.markdown(f"**Election phase**: {_phase_badge()}")

    if S.authority is not None:
        st.markdown(f"**Election**: `{S.public_params['election_id']}`")
        n_cand = S.public_params["num_candidates"]
        st.markdown(f"**Candidates**: {n_cand}")
        st.markdown(f"**Registered**: {len(S.voters)}")
        voted = sum(1 for l in S.vote_log if l.get("accepted") is True)
        st.markdown(f"**Votes cast**: {voted}")

    if S.eth_bridge is not None:
        s = S.eth_bridge.summary()
        st.divider()
        st.markdown("**🔗 Ethereum**")
        st.code(s["contract_address"][:20] + "…", language=None)
        st.markdown(f"On-chain votes: **{s['total_votes']}**")
        st.markdown(f"Network: `{s['network'][:30]}…`" if len(s['network']) > 30
                    else f"Network: `{s['network']}`")

    st.divider()
    st.markdown(
        "**Crypto stack**\n"
        "- ML-KEM-768 (NIST FIPS 203)\n"
        "- ML-DSA-65  (NIST FIPS 204)\n"
        "- TenSEAL BFV (FHE)\n"
        "- Lattice ZKP (Ajtai + FS)\n"
        "- BioHashing (SOCOFing)\n"
        "- SHA3-256 blockchain\n"
        "- EVM smart contract\n"
    )


# ── Tabs ──────────────────────────────────────────────────────────────────────

tab_setup, tab_reg, tab_vote, tab_results, tab_chain = st.tabs([
    "🏛️ Setup",
    "📋 Register",
    "🗳️ Vote",
    "📊 Results",
    "⛓️ Blockchain",
])


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 1 — SETUP
# ═══════════════════════════════════════════════════════════════════════════════

with tab_setup:
    st.header("🏛️ Election Setup")
    st.caption("Configure the election, generate post-quantum keys, deploy Ethereum contract.")

    if S.phase != "setup":
        st.info(f"Election already initialised ({_phase_badge()}).  "
                "Refresh the page to start a new election.")
    else:
        col1, col2 = st.columns([3, 2])

        with col1:
            with st.form("setup_form"):
                st.subheader("Election Configuration")
                election_id = st.text_input(
                    "Election ID", value="GeneralElection2024",
                    help="Unique identifier embedded in every ZKP and signature."
                )
                raw_candidates = st.text_area(
                    "Candidates (one per line)",
                    value="Modi\nRahul\nKejriwal\nMamta",
                    height=120,
                )
                st.divider()
                st.subheader("Cryptographic Parameters")

                c1, c2 = st.columns(2)
                with c1:
                    st.markdown("**PQ-KEM**: `ML-KEM-768`")
                    st.markdown("**PQ-Sign**: `ML-DSA-65`")
                with c2:
                    st.markdown("**FHE**: `TenSEAL BFV`")
                    st.markdown("**ZKP**: `Ajtai + Fiat-Shamir`")

                st.subheader("Ethereum Contract")
                eth_rpc = st.text_input(
                    "Ethereum RPC URL (optional)",
                    placeholder="Leave blank for in-memory EVM",
                    help="Set to http://localhost:8545 for Ganache/Hardhat, "
                         "or an Infura/Alchemy URL for a testnet.",
                )
                eth_contract = st.text_input(
                    "Deployed Contract Address (optional)",
                    placeholder="0x… — only needed with external RPC",
                )

                submitted = st.form_submit_button(
                    "🚀 Initialize Election", type="primary", use_container_width=True
                )

            if submitted:
                candidates = [c.strip() for c in raw_candidates.strip().splitlines() if c.strip()]
                if len(candidates) < 2:
                    st.error("Please enter at least 2 candidates.")
                elif not election_id.strip():
                    st.error("Election ID cannot be empty.")
                else:
                    with st.spinner("Generating post-quantum keys and deploying contract…"):
                        try:
                            config    = ElectionConfig(election_id.strip(), candidates)
                            authority = ElectionAuthority(config)
                            bridge    = EthBridge(
                                election_id=election_id.strip(),
                                rpc_url=eth_rpc.strip() or None,
                                contract_address=eth_contract.strip() or None,
                            )

                            S.authority    = authority
                            S.eth_bridge   = bridge
                            S.public_params = authority.public_params()
                            S.phase        = "registration"
                            st.success("✅ Election initialised successfully!")
                            st.rerun()
                        except Exception as exc:
                            st.error(f"Initialisation failed: {exc}")

        with col2:
            st.subheader("System Architecture")
            st.markdown("""
```
Voter Client
 ├─ ML-KEM-768 keypair
 ├─ ML-DSA-65  keypair
 ├─ BioHash (cancellable fingerprint)
 ├─ FHE encrypt (TenSEAL BFV)
 └─ Lattice ZKP (range proof)
         │
         ▼
Election Authority
 ├─ Verify ML-DSA-65 signature
 ├─ Verify ZKP
 ├─ FHE homomorphic tally
 ├─ PQ-Blockchain (SHA3+ML-DSA)
 └─ Ethereum bridge
         │
         ▼
EVM Smart Contract
 (VotingLedger.sol)
 ├─ Nullifier registry
 ├─ encVoteHash anchors
 ├─ ZKP hash anchors
 └─ Merkle root log
```
            """)

    # Show status if initialised
    if S.authority is not None and S.public_params is not None:
        st.divider()
        st.subheader("Cryptographic Setup Status")

        c1, c2, c3 = st.columns(3)
        with c1:
            st.success("✅ PQ Key Pair")
            pk_hex = S.public_params["authority_sig_pk"].hex()
            st.code(f"ML-DSA-65 pk:\n{pk_hex[:32]}…\n{pk_hex[-16:]}", language=None)
        with c2:
            st.success("✅ FHE Context")
            st.code(
                f"Scheme: BFV\n"
                f"poly_mod_degree: 4096\n"
                f"plain_modulus: 1032193\n"
                f"Candidates: {S.public_params['num_candidates']}",
                language=None
            )
        with c3:
            st.success("✅ Ethereum Contract")
            if S.eth_bridge:
                s = S.eth_bridge.summary()
                st.code(
                    f"Address:\n{s['contract_address']}\n\n"
                    f"Deploy tx:\n{s['deploy_tx'][:32]}…\n\n"
                    f"Network: {s['network'][:40]}",
                    language=None
                )


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 2 — REGISTER
# ═══════════════════════════════════════════════════════════════════════════════

with tab_reg:
    st.header("📋 Voter Registration")
    st.caption("Enrol voters with cancellable biometric templates (PQ-encrypted with ML-KEM-768).")

    if S.phase == "setup":
        st.warning("⚠️ Complete the **Setup** tab first.")
    elif S.phase in ("closed", "finalized"):
        st.info("Registration is closed.")
    else:
        col1, col2 = st.columns([2, 3])

        with col1:
            st.subheader("Enrol New Voter")
            with st.form("reg_form"):
                voter_id = st.text_input(
                    "Voter ID",
                    placeholder="e.g. VOTER-001",
                    help="Unique identifier for this voter."
                )
                pin = st.text_input(
                    "Biometric PIN",
                    type="password",
                    value="secret123",
                    help="Secret token used to derive the cancellable BioHash transform."
                )
                fp_mode = st.radio(
                    "Fingerprint source",
                    ["Upload image", "Generate synthetic"],
                    horizontal=True,
                )
                uploaded_fp = None
                if fp_mode == "Upload image":
                    uploaded_fp = st.file_uploader(
                        "Fingerprint image",
                        type=["bmp", "png", "jpg", "jpeg"],
                        help="SOCOFing format: grayscale fingerprint BMP/PNG.",
                    )

                register_btn = st.form_submit_button(
                    "📋 Register Voter", type="primary", use_container_width=True
                )

            if register_btn:
                voter_id = voter_id.strip()
                if not voter_id:
                    st.error("Voter ID is required.")
                elif voter_id in S.voters:
                    st.error(f"Voter '{voter_id}' already registered.")
                elif not pin:
                    st.error("PIN is required.")
                else:
                    with st.spinner(f"Enrolling {voter_id}…"):
                        try:
                            # Fingerprint
                            if fp_mode == "Upload image" and uploaded_fp:
                                enrol_path  = _save_upload(uploaded_fp, f"enrol_{voter_id}")
                                verify_path = enrol_path
                            else:
                                enrol_path  = _synth_fp(voter_id, variant=0)
                                verify_path = _synth_fp(voter_id, variant=1)

                            # Create voter
                            voter = Voter(voter_id, S.public_params)
                            token = _token(voter_id, pin)

                            # Register with authority (biometric enrolment)
                            S.authority.register_voter(
                                voter_id,
                                voter.kem_pk,
                                voter.sig_pk,
                                enrol_path,
                                token,
                            )

                            S.voters[voter_id]       = voter
                            S.voter_tokens[voter_id] = token
                            S.voter_fps[voter_id]    = {
                                "enrol":  enrol_path,
                                "verify": verify_path,
                            }
                            st.success(f"✅ Voter **{voter_id}** enrolled successfully!")
                        except Exception as exc:
                            st.error(f"Registration failed: {exc}")

        with col2:
            st.subheader(f"Registered Voters ({len(S.voters)})")
            if not S.voters:
                st.info("No voters registered yet.")
            else:
                for vid, v in S.voters.items():
                    reg = S.authority._registry.get(vid)
                    voted = reg.has_voted if reg else False
                    status = "✅ Voted" if voted else "⏳ Pending"
                    with st.expander(f"👤 {vid}  —  {status}"):
                        c1, c2 = st.columns(2)
                        with c1:
                            st.markdown(f"**Voter ID**: `{vid}`")
                            fp_info = S.voter_fps.get(vid, {})
                            if fp_info.get("enrol") and os.path.exists(fp_info["enrol"]):
                                st.image(fp_info["enrol"], caption="Enrolled fingerprint", width=120)
                        with c2:
                            sig_pk_hex = v.sig_pk.hex()
                            st.markdown("**ML-DSA-65 public key (first 32B)**:")
                            st.code(sig_pk_hex[:64] + "…", language=None)
                            kem_pk_hex = v.kem_pk.hex()
                            st.markdown("**ML-KEM-768 public key (first 32B)**:")
                            st.code(kem_pk_hex[:64] + "…", language=None)

        if S.phase == "registration" and len(S.voters) > 0:
            st.divider()
            if st.button("▶️ Open Voting", type="primary"):
                S.phase = "voting"
                st.rerun()


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 3 — VOTE
# ═══════════════════════════════════════════════════════════════════════════════

with tab_vote:
    st.header("🗳️ Cast Your Vote")
    st.caption("Step 1: Biometric authentication → Step 2: Encrypted ballot (only if verified).")

    if S.phase == "setup":
        st.warning("⚠️ Complete the **Setup** tab first.")
    elif S.phase == "registration":
        st.warning("⚠️ Open voting first (click ▶️ Open Voting in the Register tab).")
    elif S.phase in ("closed", "finalized"):
        st.info("Voting is closed.")
    else:
        col1, col2 = st.columns([2, 3])

        with col1:
 claude/post-quantum-evoting-system-W2QQV
            # ── STEP 1: Biometric Authentication ─────────────────────────
            st.subheader("Step 1 — Biometric Authentication")

            voter_ids    = list(S.voters.keys())
            eligible_ids = [
                vid for vid in voter_ids
                if not S.authority._registry.get(vid) or
                   not S.authority._registry.get(vid).has_voted
            ]

            with st.form("auth_form"):
=======
            st.subheader("Ballot")

            with st.form("vote_form"):
                voter_ids     = list(S.voters.keys())
                eligible_ids  = [
                    vid for vid in voter_ids
                    if not S.authority._registry.get(vid) or
                       not S.authority._registry.get(vid).has_voted
                ]
 main
                selected_voter = st.selectbox(
                    "Select voter",
                    options=eligible_ids,
                    placeholder="Choose voter ID…",
                )
                pin_vote = st.text_input(
                    "Biometric PIN",
                    type="password",
                    value="secret123",
                    help="Must match the PIN used during registration.",
                )
                fp_vote_mode = st.radio(
                    "Fingerprint (authentication)",
                    ["Use enrolled image", "Upload new image"],
                    horizontal=True,
                )
                uploaded_vote_fp = None
                if fp_vote_mode == "Upload new image":
                    uploaded_vote_fp = st.file_uploader(
                        "Authentication fingerprint",
                        type=["bmp", "png", "jpg", "jpeg"],
                        key="vote_fp",
                    )
                auth_btn = st.form_submit_button(
                    "🔐 Authenticate", type="primary", use_container_width=True
                )

            if auth_btn and selected_voter:
                token = _token(selected_voter, pin_vote)
                if fp_vote_mode == "Upload new image" and uploaded_vote_fp:
                    verify_path = _save_upload(
                        uploaded_vote_fp, f"verify_{selected_voter}"
                    )
                else:
                    # Use the EXACT enrolled image — guarantees biometric check
                    # tests the fingerprint, not a different synthetic variant
                    verify_path = S.voter_fps[selected_voter]["enrol"]

                with st.spinner("Running biometric verification…"):
                    try:
                        ok, score = S.authority.authenticate(
                            selected_voter, verify_path, token
                        )
                        S.auth_result = {
                            "voter_id": selected_voter,
                            "ok":       ok,
                            "score":    score,
                        }
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Authentication error: {exc}")

            # ── Authentication result gate ────────────────────────────────
            if S.auth_result is not None:
                ar = S.auth_result

                if not ar["ok"]:
                    # ── HARD BLOCK: biometric failed ─────────────────────
                    st.error(
                        f"❌ **Biometric authentication FAILED**  \n"
                        f"BioHash similarity = **{ar['score']:.3f}** "
                        f"(required ≥ {BIO_MATCH_THRESHOLD})"
                    )
                    st.warning(
                        "🚫 **Vote BLOCKED** — a valid biometric match is "
                        "required before a ballot can be cast. "
                        "Verify your PIN and fingerprint, then try again."
                    )
                    # Log once only (prevent duplicate entries on reruns)
                    if not ar.get("logged"):
                        S.vote_log.append({
                            "voter_id":  ar["voter_id"],
                            "candidate": "—",
                            "accepted":  False,
                            "reason":    "Biometric auth failed",
                            "bio_score": ar["score"],
                            "timestamp": time.time(),
                        })
                        ar["logged"] = True
                    if st.button("🔄 Try Again", key="retry_auth"):
                        S.auth_result = None
                        st.rerun()

                else:
                    # ── Biometric PASSED: show ballot ─────────────────────
                    st.success(
                        f"✅ **Biometric VERIFIED** — "
                        f"BioHash similarity: **{ar['score']:.3f}**"
                    )

                    reg = S.authority._registry.get(ar["voter_id"])
                    if reg and reg.has_voted:
                        st.warning(f"⚠️ Voter **{ar['voter_id']}** has already voted.")
                        S.auth_result = None
                    else:
                        st.subheader("Step 2 — Cast Your Ballot")
                        st.info(
                            f"Casting as: **{ar['voter_id']}**  "
                            f"| Authentication score: {ar['score']:.3f}"
                        )

                        candidates = S.public_params["candidates"]
                        with st.form("ballot_form"):
                            choice_label  = st.radio(
                                "Choose candidate", options=candidates
                            )
                            candidate_idx = candidates.index(choice_label)
                            cast_btn = st.form_submit_button(
                                "🗳️ Cast Encrypted Vote",
                                type="primary",
                                use_container_width=True,
                            )

                        if cast_btn:
                            with st.spinner("Encrypting vote and generating ZKP…"):
                                try:
                                    ballot   = S.voters[ar["voter_id"]].cast_vote(
                                        candidate_idx
                                    )
                                    accepted = S.authority.receive_vote(ballot)

                                    if accepted:
                                        nullifier_b = sha3_256(
                                            bytes.fromhex(
                                                ballot["zkp_proof"]["voter_id_hash"]
                                            ) + S.voters[ar["voter_id"]].sig_pk
                                        )
                                        enc_hash_b = sha3_256(
                                            bytes.fromhex(ballot["encrypted_vote_hex"])
                                        )
                                        zkp_hash_b = sha3_256(
                                            json.dumps(
                                                ballot["zkp_proof"], sort_keys=True
                                            ).encode()
                                        )
                                        tx = S.eth_bridge.anchor_vote(
                                            nullifier_b, enc_hash_b, zkp_hash_b
                                        )
                                        S.vote_log.append({
                                            "voter_id":       ar["voter_id"],
                                            "candidate":      choice_label,
                                            "accepted":       True,
                                            "bio_score":      ar["score"],
                                            "zkp_commitment": ballot["zkp_commitment"],
                                            "zkp_proof_hash": ballot["zkp_proof_hash"],
                                            "eth_tx":         tx,
                                            "encrypted_vote": ballot["encrypted_vote_hex"][:64] + "…",
                                            "timestamp":      time.time(),
                                        })
                                        st.success(
                                            f"✅ Vote cast!  "
                                            f"Ethereum tx: `{tx[:20]}…`"
                                        )
                                        S.auth_result = None   # reset for next voter
                                        st.rerun()
                                    else:
                                        S.vote_log.append({
                                            "voter_id":  ar["voter_id"],
                                            "candidate": choice_label,
                                            "accepted":  False,
                                            "reason":    "Authority rejected (ZKP/sig invalid or double-vote)",
                                            "bio_score": ar["score"],
                                            "timestamp": time.time(),
                                        })
                                        st.error("❌ Vote rejected by authority.")
                                except Exception as exc:
                                    st.error(f"Error casting vote: {exc}")

        with col2:
            st.subheader("Vote Log")
            if not S.vote_log:
                st.info("No votes cast yet.")
            else:
                for entry in reversed(S.vote_log):
                    color = "#4caf50" if entry.get("accepted") else "#f44336"
                    tag   = "ACCEPTED" if entry.get("accepted") else "REJECTED"
                    with st.container():
                        st.markdown(
                            f'<div class="chain-block">'
                            f'<span style="color:{color};font-weight:bold">{tag}</span>'
                            f' &nbsp; {entry["voter_id"]} → <b>{entry["candidate"]}</b>'
                            f' &nbsp; | BioHash: {entry.get("bio_score", 0):.3f}'
                            f'</div>',
                            unsafe_allow_html=True,
                        )
                        if entry.get("accepted"):
                            with st.expander("📄 Vote receipt"):
                                st.markdown(
                                    f'<div class="vote-receipt">'
                                    f'Voter ID hash : {sha3_256(entry["voter_id"].encode()).hex()}<br>'
                                    f'ZKP commitment: {entry.get("zkp_commitment","—")}<br>'
                                    f'ZKP proof hash: {entry.get("zkp_proof_hash","—")}<br>'
                                    f'FHE ciphertext: {entry.get("encrypted_vote","—")}<br>'
                                    f'Ethereum tx   : {entry.get("eth_tx","—")}'
                                    f'</div>',
                                    unsafe_allow_html=True,
                                )

        if S.phase == "voting":
            st.divider()
            if st.button("🔒 Close Voting", type="secondary"):
                S.phase = "closed"
                st.rerun()


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 4 — RESULTS
# ═══════════════════════════════════════════════════════════════════════════════

with tab_results:
    st.header("📊 Election Results")
    st.caption("FHE decryption (single operation) → ML-DSA-65 signed results → Ethereum finalization.")

    if S.phase not in ("closed", "finalized"):
        st.info("Results will be available after voting is closed.")
        if S.phase == "voting" and len(S.vote_log) > 0:
            st.button(
                "🔒 Close & Finalize Election",
                type="primary",
                key="close_from_results",
                on_click=lambda: S.__setitem__("phase", "closed"),
            )
    else:
        if S.phase == "closed" and S.results is None:
            with st.spinner("Decrypting FHE tally and signing results…"):
                try:
                    results = S.authority.finalize()

                    # Anchor results on Ethereum
                    res_bytes    = json.dumps(
                        {k: v for k, v in results.items()
                         if k not in ("authority_signature", "authority_sig_pk")},
                        sort_keys=True,
                    ).encode()
                    res_hash     = sha3_256(res_bytes)
                    sig_bytes    = bytes.fromhex(results["authority_signature"])

                    # Mine PQ-blockchain batch first
                    S.chain_stats = S.authority.chain_stats()

                    # Anchor on Ethereum
                    for blk in S.authority._chain.chain[1:]:
                        S.eth_bridge.record_batch(blk.hash, len(blk.votes))

                    finalize_tx = S.eth_bridge.finalize_election(res_hash, sig_bytes)

                    S.results    = results
                    S.finalize_tx = finalize_tx
                    S.phase      = "finalized"
                except Exception as exc:
                    st.error(f"Finalization error: {exc}")

        if S.results:
            results   = S.results
            counts    = results["results"]
            total     = results["total_votes"]
            winner    = results["winner"]
            candidates = results["candidates"]

            # ── Winner banner ─────────────────────────────────────────────
            st.success(f"🏆  **Winner: {winner}**  —  Total votes: {total}")

            # ── Bar chart ─────────────────────────────────────────────────
            fig = go.Figure(
                data=[go.Bar(
                    x=candidates,
                    y=[counts.get(c, 0) for c in candidates],
                    marker_color=[
                        "#4c8df5" if c != winner else "#4caf50"
                        for c in candidates
                    ],
                    text=[
                        f"{counts.get(c, 0)}<br>({counts.get(c,0)/total*100:.1f}%)"
                        if total > 0 else "0"
                        for c in candidates
                    ],
                    textposition="outside",
                )]
            )
            fig.update_layout(
                title="Vote Tally (FHE-decrypted)",
                xaxis_title="Candidate",
                yaxis_title="Votes",
                plot_bgcolor="#0e1117",
                paper_bgcolor="#0e1117",
                font_color="#ffffff",
                height=400,
            )
            st.plotly_chart(fig, use_container_width=True)

            # ── Vote breakdown in words ───────────────────────────────────
            st.divider()
            st.subheader("📋 Detailed Vote Breakdown")

            sorted_cands = sorted(
                candidates, key=lambda c: counts.get(c, 0), reverse=True
            )
            for rank, cand in enumerate(sorted_cands, 1):
                cnt = counts.get(cand, 0)
                pct = cnt / total * 100 if total > 0 else 0
                votes_word = "vote" if cnt == 1 else "votes"
                if cand == winner:
                    st.markdown(
                        f"🏆 **1st place — {cand} *(Winner)* **: "
                        f"**{cnt} {votes_word}** ({pct:.1f}% of total)"
                    )
                else:
                    st.markdown(
                        f"**#{rank} — {cand}**: "
                        f"{cnt} {votes_word} ({pct:.1f}% of total)"
                    )

            st.markdown(f"**Total votes cast**: {total}")

            nullified = results.get("nullified_count", 0)
            bio_blocked = sum(
                1 for l in S.vote_log
                if not l.get("accepted") and l.get("reason") == "Biometric auth failed"
            )
            if bio_blocked or nullified:
                st.markdown(
                    f"**Biometric-blocked attempts**: {bio_blocked} "
                    f"(votes blocked at auth gate — NOT counted)"
                )
            if nullified:
                st.warning(
                    f"⚠️ {nullified} voter(s) passed biometric but no ballot was "
                    "received — their auth token was nullified at finalization."
                )

            if len(sorted_cands) > 1:
                top   = counts.get(sorted_cands[0], 0)
                runup = counts.get(sorted_cands[1], 0)
                margin = top - runup
                st.markdown(
                    f"**Margin of victory**: {margin} vote{'s' if margin != 1 else ''} "
                    f"({winner} over {sorted_cands[1]})"
                )

            # ── Verification details ──────────────────────────────────────
            col1, col2 = st.columns(2)

            with col1:
                st.subheader("Cryptographic Verification")
                # Verify ML-DSA-65 signature
                sig_pk  = bytes.fromhex(results.get("authority_sig_pk", ""))
                sig_raw = bytes.fromhex(results.get("authority_signature", ""))
                payload = json.dumps(
                    {k: v for k, v in results.items()
                     if k not in ("authority_signature","authority_sig_pk")},
                    sort_keys=True,
                ).encode()
                sig_ok = pq_verify(sig_pk, payload, sig_raw) if sig_pk else False
                st.markdown(
                    f"ML-DSA-65 result signature: {'✅ VALID' if sig_ok else '❌ INVALID'}"
                )
                st.markdown(
                    f"PQ-Blockchain valid: "
                    f"{'✅ VALID' if S.chain_stats.get('chain_valid') else '❌ INVALID'}"
                )
                st.markdown(
                    f"FHE scheme: **TenSEAL BFV** — decrypted once after poll closed"
                )

            with col2:
                st.subheader("Ethereum Anchor")
                if S.finalize_tx:
                    st.markdown(f"**Finalization tx**: `{S.finalize_tx}`")
                if S.eth_bridge:
                    s = S.eth_bridge.summary()
                    st.markdown(f"**Contract**: `{s['contract_address']}`")
                    st.markdown(f"**Total on-chain votes**: {s['total_votes']}")
                    st.markdown(f"**Merkle batches**: {s['merkle_roots']}")
                    st.markdown(f"**Election open**: {s['is_open']}")


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 5 — BLOCKCHAIN EXPLORER
# ═══════════════════════════════════════════════════════════════════════════════

with tab_chain:
    st.header("⛓️ Blockchain Explorer")
    st.caption("PQ-blockchain (SHA3+ML-DSA) + Ethereum smart contract event log.")

    if S.authority is None:
        st.info("Initialise the election first.")
    else:
        tab_pq, tab_eth = st.tabs(["🔐 PQ Blockchain", "🌐 Ethereum Contract"])

        # ── PQ Blockchain ────────────────────────────────────────────────────
        with tab_pq:
            stats = S.authority.chain_stats()
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Chain length",   stats.get("chain_length", 0))
            c2.metric("Votes on-chain", stats.get("total_votes",  0))
            c3.metric("Pending votes",  stats.get("pending_votes",0))
            c4.metric(
                "Chain valid",
                "✅ YES" if stats.get("chain_valid") else "❌ NO"
            )

            st.divider()
            chain = S.authority._chain.chain
            for blk in reversed(chain):
                header_color = "#2a3a6a" if blk.index > 0 else "#1e3a2a"
                with st.expander(
                    f"Block #{blk.index}  —  "
                    f"{len(blk.votes)} votes  —  hash: {blk.hash[:20]}…"
                ):
                    c1, c2 = st.columns(2)
                    with c1:
                        st.markdown(f"**Index**: `{blk.index}`")
                        st.markdown(
                            f"**Timestamp**: `{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(blk.timestamp))}`"
                        )
                        st.markdown(f"**Prev hash**: `{blk.prev_hash[:32]}…`")
                        st.markdown(f"**Nonce** (PoW): `{blk.nonce}`")
                    with c2:
                        st.markdown(f"**Hash**: `{blk.hash}`")
                        st.markdown(f"**Merkle root**: `{blk.merkle_root[:32]}…`")
                        sig_ok = blk.verify_signature(
                            S.authority._kp.sig_pk
                        )
                        st.markdown(
                            f"**ML-DSA-65 sig**: {'✅ VALID' if sig_ok else '❌ INVALID'}"
                        )
                    if blk.votes:
                        st.divider()
                        st.markdown("**Vote Records (encrypted)**")
                        for i, vote in enumerate(blk.votes):
                            st.markdown(
                                f'<div class="event-row">'
                                f'[{i}] voter: {vote.voter_id_hash[:16]}…  '
                                f'enc_vote: {vote.encrypted_vote[:24]}…  '
                                f'zkp: {vote.zkp_commitment[:16]}…'
                                f'</div>',
                                unsafe_allow_html=True,
                            )

        # ── Ethereum Contract ────────────────────────────────────────────────
        with tab_eth:
            if S.eth_bridge is None:
                st.info("Ethereum bridge not initialised.")
            else:
                s = S.eth_bridge.summary()

                c1, c2, c3, c4 = st.columns(4)
                c1.metric("On-chain votes",   s["total_votes"])
                c2.metric("Merkle batches",   s["merkle_roots"])
                c3.metric("Chain ID",         s["chain_id"])
                c4.metric("Election open",    "✅" if s["is_open"] else "🔒 Closed")

                st.divider()
                st.markdown(f"**Contract address**: `{s['contract_address']}`")
                st.markdown(f"**Deploy tx**: `{s['deploy_tx']}`")
                st.markdown(f"**Network**: `{s['network']}`")
                st.markdown(f"**Solidity source**: `contracts/VotingLedger.sol`")

                merkle_roots = S.eth_bridge.get_all_merkle_roots()
                if merkle_roots:
                    st.divider()
                    st.markdown("**Anchored PQ-Blockchain Merkle Roots**")
                    for i, root in enumerate(merkle_roots):
                        st.code(f"Batch {i}: {root}", language=None)

                events = S.eth_bridge.get_events()
                if events:
                    st.divider()
                    st.markdown(f"**Event Log ({len(events)} events)**")
                    for ev in reversed(events):
                        colour = {
                            "VoteAnchored":       "#4c8df5",
                            "BatchRecorded":      "#f5a623",
                            "ElectionFinalized":  "#4caf50",
                        }.get(ev["event"], "#888")

                        args_str = "  ".join(
                            f"{k}: {str(v)[:20]}…" if len(str(v)) > 20 else f"{k}: {v}"
                            for k, v in ev["args"].items()
                        )
                        st.markdown(
                            f'<div class="event-row" style="border-left-color:{colour}">'
                            f'<b style="color:{colour}">{ev["event"]}</b>'
                            f' | tx: {ev["txHash"][:20]}…'
                            f' | block: {ev["blockNumber"]}<br>'
                            f'<span style="color:#aaa">{args_str}</span>'
                            f'</div>',
                            unsafe_allow_html=True,
                        )

                evidence = S.eth_bridge.get_evidence()
                if evidence:
                    st.divider()
                    st.markdown(f"**Anchored Vote Evidence ({len(evidence)} records)**")
                    for i, e in enumerate(evidence):
                        with st.expander(f"Evidence #{i} — block {e['blockNumber']}"):
                            st.markdown(f"**Nullifier**: `{e['nullifier']}`")
                            st.markdown(f"**FHE hash**:  `{e['encVoteHash']}`")
                            st.markdown(f"**ZKP hash**:  `{e['zkpHash']}`")
                            st.markdown(
                                f"**Timestamp**: `{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(e['timestamp']))}`"
                            )
