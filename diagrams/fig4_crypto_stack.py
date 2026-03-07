"""
Figure 4: Cryptographic Stack & ZKP Protocol
Two-panel figure: (a) layered crypto stack, (b) ZKP Sigma protocol
"""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
import matplotlib.patches as mpatches
import numpy as np

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(18, 11))
fig.patch.set_facecolor('#FAFAFA')

# ══════════════════════════════════════════════════════════════════════════════
# LEFT PANEL — Cryptographic Stack
# ══════════════════════════════════════════════════════════════════════════════
ax1.set_xlim(0, 9)
ax1.set_ylim(0, 11)
ax1.axis('off')

ax1.text(4.5, 10.6, 'Cryptographic Stack',
         ha='center', fontsize=13, fontweight='bold', color='#1A237E')
ax1.plot([0.3, 8.7], [10.35, 10.35], color='#1A237E', lw=1.5)

layers = [
    # (y, h, label, sublabel, face, edge)
    (9.4,  0.75, 'APPLICATION LAYER',
     'ElectionAuthority  ·  VoterRegistry  ·  GUI/CLI',
     '#E8F5E9', '#2E7D32'),

    (8.45, 0.75, 'SIGNATURE LAYER  —  ML-DSA-65 (FIPS 204)',
     'Vote signing  ·  Block signing  ·  Results signing\nModule-Lattice Digital Signature Algorithm',
     '#EDE7F6', '#6A1B9A'),

    (7.5,  0.75, 'KEY ENCAPSULATION  —  ML-KEM-768 (FIPS 203)',
     'Biometric template encryption  ·  Hybrid KEM + AES-256-GCM\nModule-Lattice Key Encapsulation Mechanism',
     '#EDE7F6', '#6A1B9A'),

    (6.55, 0.75, 'HOMOMORPHIC ENCRYPTION  —  BFV / TenSEAL',
     'Vote encryption (one-hot)  ·  Homomorphic tally\nBrakerski–Fan–Vercauteren  ·  poly_mod=4096  ·  plain_mod=1032193',
     '#FBE9E7', '#BF360C'),

    (5.6,  0.75, 'ZERO-KNOWLEDGE PROOFS  —  Lattice Sigma',
     'Ajtai commitment  ·  Fiat-Shamir challenge  ·  CDS OR proofs\nProves vote ∈ {0,…,k-1} without revealing value',
     '#FFF8E1', '#E65100'),

    (4.65, 0.75, 'CANCELLABLE BIOMETRICS  —  BioHash (ISO/IEC 24745)',
     'Gabor filter bank (48 filters)  ·  HOG (8100-d)  ·  SHAKE256\nProjection onto user-token-derived orthogonal subspace → 512-bit',
     '#E0F7FA', '#006064'),

    (3.7,  0.75, 'BLOCKCHAIN LEDGER  —  SHA3-256 + ML-DSA-65',
     'Merkle tree  ·  PoW (difficulty=2)  ·  Hash chain\nNullifier registry (double-vote prevention)',
     '#ECEFF1', '#455A64'),

    (2.75, 0.75, 'ETHEREUM ANCHOR  —  Solidity 0.8.20 / EVM',
     'VotingLedger.sol  ·  nullifier mapping  ·  batch Merkle roots\nImmutable evidence registry (in-memory or live testnet)',
     '#E8EAF6', '#283593'),

    (1.5,  1.0, 'HASH & SYMMETRIC PRIMITIVES',
     'SHA3-256 / SHAKE256 (FIPS 202)  ·  AES-256-GCM (SP 800-38D)\nKey derivation  ·  Blockchain hashing  ·  Commitment binding',
     '#F3E5F5', '#4A148C'),

    (0.4,  0.85, 'QUANTUM THREAT MODEL',
     'All layers above resist Grover (hash) and Shor (discrete-log/factoring)\n→ NIST PQC Round-3 standards (FIPS 203, 204, 202)',
     '#FFEBEE', '#B71C1C'),
]

for y, h, lbl, sub, fc, ec in layers:
    rect = FancyBboxPatch((0.35, y), 8.3, h,
                          boxstyle="round,pad=0.06", linewidth=1.8,
                          edgecolor=ec, facecolor=fc, zorder=2)
    ax1.add_patch(rect)
    ax1.text(4.5, y+h-0.2, lbl, ha='center', va='top',
             fontsize=8.5, fontweight='bold', color=ec)
    ax1.text(4.5, y+0.16, sub, ha='center', va='bottom',
             fontsize=7, color='#37474F', linespacing=1.35)
    # arrow between layers
    if y > 0.4:
        ax1.annotate('', xy=(4.5, y), xytext=(4.5, y-0.01),
                     arrowprops=dict(arrowstyle='->', color='#90A4AE', lw=1))

# left panel label
ax1.text(4.5, 0.12, '(a) Layered Cryptographic Stack',
         ha='center', fontsize=9, color='#455A64', style='italic')

# ══════════════════════════════════════════════════════════════════════════════
# RIGHT PANEL — ZKP Protocol detail
# ══════════════════════════════════════════════════════════════════════════════
ax2.set_xlim(0, 9)
ax2.set_ylim(0, 11)
ax2.axis('off')

ax2.text(4.5, 10.6, 'Lattice-Based ZKP — Sigma Protocol',
         ha='center', fontsize=13, fontweight='bold', color='#1A237E')
ax2.plot([0.3, 8.7], [10.35, 10.35], color='#1A237E', lw=1.5)

C_ZKP = '#E65100'
C_VER = '#1565C0'
C_FS  = '#2E7D32'
C_RNG = '#6A1B9A'
C_bg  = '#FFF8E1'
C_bgv = '#E3F2FD'

# Column separators
ax2.plot([3.0, 3.0], [0.3, 10.2], color='#CFD8DC', lw=1, ls='--')
ax2.plot([6.0, 6.0], [0.3, 10.2], color='#CFD8DC', lw=1, ls='--')
ax2.text(1.5, 10.1, 'PROVER (Voter)', ha='center', fontsize=9,
         fontweight='bold', color=C_ZKP)
ax2.text(4.5, 10.1, 'CHANNEL', ha='center', fontsize=9,
         fontweight='bold', color=C_FS)
ax2.text(7.5, 10.1, 'VERIFIER (Authority)', ha='center', fontsize=9,
         fontweight='bold', color=C_VER)

def zbox(ax, x, y, w, h, text, fc, ec, fs=8, bold=False):
    r = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.06",
                       linewidth=1.5, edgecolor=ec, facecolor=fc, zorder=3)
    ax.add_patch(r)
    ax.text(x+w/2, y+h/2, text, ha='center', va='center',
            fontsize=fs, fontweight='bold' if bold else 'normal',
            color=ec, zorder=4, linespacing=1.3)

def zarr(ax, x1, x2, y, label, col, ret=False):
    style = '<-' if ret else '->'
    ax.annotate('', xy=(x2, y), xytext=(x1, y),
                arrowprops=dict(arrowstyle=style, color=col, lw=1.5))
    ax.text((x1+x2)/2, y+0.1, label, ha='center', va='bottom',
            fontsize=7.2, color=col, style='italic')

# ── Setup ────────────────────────────────────────────────────────────────────
zbox(ax2, 0.1, 9.05, 2.8, 0.9,
     'PUBLIC PARAMS\nA ∈ Zq^(n×m),  e₀ ∈ Zq^n\nq = 2²³-7,  n=64,  m=128',
     '#F3E5F5', C_RNG, fs=7.5)
zbox(ax2, 6.1, 9.05, 2.8, 0.9,
     'PUBLIC PARAMS\n(same A, e₀, q, n, m)',
     '#E3F2FD', C_VER, fs=7.5)

# ── Step 1 ────────────────────────────────────────────────────────────────────
y = 8.4
ax2.text(0.5, y, '①', fontsize=10, color=C_ZKP, fontweight='bold')
zbox(ax2, 0.1, 7.55, 2.8, 0.75,
     'Sample r ∈ Zq^m,  ρ_r ∈ Zq^m,  ρ_v ∈ Zq\nCommit:  C = Ar + v·e₀  (mod q)\nAnnounce:  w = Aρ_r + ρ_v·e₀',
     C_bg, C_ZKP, fs=7.5)
zarr(ax2, 2.9, 4.2, 7.95, 'C, w', C_ZKP)

# ── Step 2 ────────────────────────────────────────────────────────────────────
y = 7.3
ax2.text(4.5, y, '② Fiat-Shamir', ha='center', fontsize=8,
         color=C_FS, fontweight='bold')
zbox(ax2, 3.1, 6.85, 2.8, 0.35,
     'c = SHA3(w ‖ C ‖ context)  mod q',
     '#E8F5E9', C_FS, fs=7.5)
zarr(ax2, 3.1, 0.9+2.0, 7.0, 'c (challenge)', C_FS, ret=True)

# ── Step 3 ────────────────────────────────────────────────────────────────────
y = 6.6
ax2.text(0.5, y, '③', fontsize=10, color=C_ZKP, fontweight='bold')
zbox(ax2, 0.1, 5.8, 2.8, 0.72,
     'Respond:\nz_r = ρ_r + c·r  (mod q)\nz_v = ρ_v + c·v  (mod q)',
     C_bg, C_ZKP, fs=7.5)
zarr(ax2, 2.9, 5.95, 6.2, 'z_r, z_v', C_ZKP)

# ── Step 4 ────────────────────────────────────────────────────────────────────
y = 5.6
ax2.text(6.5, y, '④', fontsize=10, color=C_VER, fontweight='bold')
zbox(ax2, 6.1, 5.0, 2.8, 0.5,
     'Verify:\nAz_r + z_v·e₀ ≡ w + c·C  (mod q)',
     C_bgv, C_VER, fs=7.5)

# ── Range Proof ───────────────────────────────────────────────────────────────
ax2.plot([0.1, 8.9], [4.75, 4.75], color='#CFD8DC', lw=1.2, ls='-.')
ax2.text(4.5, 4.6, 'Range Proof Extension  (vote ∈ {0, …, k−1})',
         ha='center', fontsize=9, fontweight='bold', color=C_RNG)

zbox(ax2, 0.1, 3.55, 2.8, 0.9,
     'Binary decompose v = Σ bᵢ·2ⁱ\nFor each bit bᵢ ∈ {0,1}:\n  CDS 1-of-2 OR proof',
     C_bg, C_RNG, fs=7.5)

zbox(ax2, 3.1, 3.55, 2.8, 0.9,
     'Consistency hash:\nSHA3(main_comm ‖\n  bit_comms ‖ ctx)',
     '#E8F5E9', C_FS, fs=7.5)

zbox(ax2, 6.1, 3.55, 2.8, 0.9,
     'Verify each bᵢ proof\nVerify consistency\nhash matches',
     C_bgv, C_VER, fs=7.5)

# ── Security note ─────────────────────────────────────────────────────────────
zbox(ax2, 0.1, 2.65, 8.8, 0.7,
     'Security:  Binding from Module-SIS hardness  ·  Hiding from LWE  '
     '·  Zero-Knowledge: proof ∄ plaintext vote\n'
     'Params:  q=2²³−7  n=64  m=128  β=800  (∞-norm bound)',
     '#F3E5F5', C_RNG, fs=7.8)

# ── FHE mini-diagram ──────────────────────────────────────────────────────────
ax2.plot([0.1, 8.9], [2.45, 2.45], color='#CFD8DC', lw=1.2, ls='-.')
ax2.text(4.5, 2.3, 'FHE Tally — BFV Homomorphic Accumulation',
         ha='center', fontsize=9, fontweight='bold', color='#BF360C')

fhe_boxes = [
    (0.1,  1.4, 'Vote₁\nenc([0,1,0,…])'),
    (2.3,  1.4, 'Vote₂\nenc([1,0,0,…])'),
    (4.5,  1.4, 'Vote_N\nenc([0,0,1,…])'),
    (3.1,  0.3, 'Σ enc(votes)\n→ ONE decrypt → [cnt₀, cnt₁, …]'),
]
for x, y, t in fhe_boxes[:3]:
    zbox(ax2, x, y, 1.9, 0.65, t, '#FBE9E7', '#BF360C', fs=7.5)
zbox(ax2, 3.1, 0.3, 2.8, 0.75,
     'Σ enc(votes) → ONE decrypt\n→ [cnt₀, cnt₁, …, cnt_k]',
     '#FBE9E7', '#BF360C', fs=8, bold=True)
for x in [1.0, 3.2, 5.4]:
    ax2.annotate('', xy=(4.5, 1.05), xytext=(x, 1.4),
                 arrowprops=dict(arrowstyle='->', color='#BF360C', lw=1.2))
ax2.text(4.4, 1.7, '⊕  ⊕  …  ⊕', ha='center', fontsize=11, color='#BF360C')

ax2.text(4.5, 0.12, '(b) ZKP Sigma Protocol + FHE Tallying',
         ha='center', fontsize=9, color='#455A64', style='italic')

plt.tight_layout(pad=0.4)
plt.savefig('/home/user/RE-code/diagrams/fig4_crypto_stack_zkp.png',
            dpi=200, bbox_inches='tight', facecolor='#FAFAFA')
plt.close()
print("Fig 4 saved.")
