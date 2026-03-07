"""
Figure 1: System Architecture Overview
Post-Quantum Secure E-Voting System
"""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

fig, ax = plt.subplots(1, 1, figsize=(18, 13))
ax.set_xlim(0, 18)
ax.set_ylim(0, 13)
ax.axis('off')
fig.patch.set_facecolor('#F8F9FA')

# ── colour palette ──────────────────────────────────────────────────────────
C = {
    'voter':   '#2196F3',
    'auth':    '#4CAF50',
    'crypto':  '#9C27B0',
    'fhe':     '#FF5722',
    'zkp':     '#FF9800',
    'chain':   '#607D8B',
    'eth':     '#3F51B5',
    'bio':     '#00BCD4',
    'header':  '#1A237E',
    'bg':      '#FFFFFF',
    'lblue':   '#E3F2FD',
    'lgreen':  '#E8F5E9',
    'lpurple': '#F3E5F5',
    'lorange': '#FFF3E0',
    'lgrey':   '#ECEFF1',
    'lindigo': '#E8EAF6',
    'lcyan':   '#E0F7FA',
}

def box(ax, x, y, w, h, label, sub=None, color='#FFFFFF', lcolor='#000000',
        fs=9, lfs=7.5, bold=False, radius=0.25):
    rect = FancyBboxPatch((x, y), w, h,
                          boxstyle=f"round,pad=0.05,rounding_size={radius}",
                          linewidth=1.4, edgecolor=lcolor,
                          facecolor=color, zorder=3)
    ax.add_patch(rect)
    weight = 'bold' if bold else 'normal'
    ty = y + h/2 + (0.18 if sub else 0)
    ax.text(x + w/2, ty, label, ha='center', va='center',
            fontsize=fs, fontweight=weight, color=lcolor, zorder=4)
    if sub:
        ax.text(x + w/2, y + h/2 - 0.22, sub, ha='center', va='center',
                fontsize=lfs, color=lcolor, alpha=0.85, zorder=4)

def arrow(ax, x1, y1, x2, y2, color='#555555', style='->', lw=1.4,
          label=None, lfs=7.5):
    ax.annotate('', xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle=style, color=color,
                                lw=lw, connectionstyle='arc3,rad=0.0'))
    if label:
        mx, my = (x1+x2)/2, (y1+y2)/2
        ax.text(mx, my+0.13, label, ha='center', va='bottom',
                fontsize=lfs, color=color)

# ── title ────────────────────────────────────────────────────────────────────
ax.text(9, 12.55, 'Post-Quantum Secure E-Voting System — Architecture',
        ha='center', va='center', fontsize=14, fontweight='bold',
        color=C['header'])
ax.plot([0.4, 17.6], [12.25, 12.25], color=C['header'], lw=1.5)

# ══════════════════════════════════════════════════════════════════════════════
# ROW 1 — Voter Client (left) + Election Authority (centre+right)
# ══════════════════════════════════════════════════════════════════════════════

# ── Voter Client panel ───────────────────────────────────────────────────────
vpanel = FancyBboxPatch((0.3, 6.8), 3.8, 5.1,
    boxstyle="round,pad=0.1", linewidth=2,
    edgecolor=C['voter'], facecolor=C['lblue'], zorder=1)
ax.add_patch(vpanel)
ax.text(2.2, 11.65, 'VOTER CLIENT', ha='center', fontsize=9,
        fontweight='bold', color=C['voter'])

box(ax, 0.55, 10.35, 3.3, 0.85, 'Voter Interface',
    'Register / Authenticate / Vote',
    C['lblue'], C['voter'], fs=8.5, bold=True)
box(ax, 0.55, 9.2, 3.3, 0.85, 'ML-KEM-768 + ML-DSA-65',
    'Key Generation (per voter)',
    '#EDE7F6', C['crypto'], fs=8, bold=False)
box(ax, 0.55, 8.1, 3.3, 0.85, 'FHE Ballot Encryption',
    'BFV one-hot vector encryption',
    '#FBE9E7', C['fhe'], fs=8)
box(ax, 0.55, 7.0, 3.3, 0.85, 'ZKP Vote Range Proof',
    'Ajtai commitment + Sigma protocol',
    '#FFF8E1', C['zkp'], fs=8)

# ── Election Authority panel ─────────────────────────────────────────────────
apanel = FancyBboxPatch((4.5, 6.8), 9.0, 5.1,
    boxstyle="round,pad=0.1", linewidth=2,
    edgecolor=C['auth'], facecolor=C['lgreen'], zorder=1)
ax.add_patch(apanel)
ax.text(9.0, 11.65, 'ELECTION AUTHORITY', ha='center', fontsize=9,
        fontweight='bold', color=C['auth'])

box(ax, 4.7, 10.35, 3.9, 0.85, 'ElectionAuthority',
    'Orchestration & Key Holder',
    C['lgreen'], C['auth'], fs=8.5, bold=True)
box(ax, 8.85, 10.35, 4.4, 0.85, 'Voter Registry',
    'Sessions · Lockout · Nullifiers',
    C['lgreen'], C['auth'], fs=8.5, bold=True)

box(ax, 4.7, 9.2, 3.9, 0.85, 'Cancellable Biometrics',
    'Gabor+HOG → BioHash (ISO/IEC 24745)',
    '#E0F7FA', C['bio'], fs=8)
box(ax, 8.85, 9.2, 4.4, 0.85, 'ML-KEM-768 / ML-DSA-65',
    'Template encryption · Block signing',
    '#EDE7F6', C['crypto'], fs=8)

box(ax, 4.7, 8.1, 3.9, 0.85, 'FHE Authority (BFV)',
    'Tally accumulation · Single decrypt',
    '#FBE9E7', C['fhe'], fs=8)
box(ax, 8.85, 8.1, 4.4, 0.85, 'ZKP Verifier',
    'Sigma + CDS OR proof verification',
    '#FFF8E1', C['zkp'], fs=8)

box(ax, 4.7, 7.0, 8.55, 0.85, 'VoteRecord Validation',
    'Signature · ZKP · Session · Nullifier → Accept / Reject',
    C['lgreen'], C['auth'], fs=8.5, bold=True)

# ══════════════════════════════════════════════════════════════════════════════
# ROW 2 — Blockchain (left-centre)  +  Ethereum Layer (right)
# ══════════════════════════════════════════════════════════════════════════════

bpanel = FancyBboxPatch((0.3, 2.6), 8.3, 3.8,
    boxstyle="round,pad=0.1", linewidth=2,
    edgecolor=C['chain'], facecolor=C['lgrey'], zorder=1)
ax.add_patch(bpanel)
ax.text(4.45, 6.17, 'PQ BLOCKCHAIN LEDGER', ha='center', fontsize=9,
        fontweight='bold', color=C['chain'])

box(ax, 0.55, 5.1, 3.7, 0.75, 'VotingBlockchain',
    'PoW · Merkle Tree · Hash Chain',
    C['lgrey'], C['chain'], fs=8.5, bold=True)
box(ax, 4.55, 5.1, 3.8, 0.75, 'Block Structure',
    'index · prev_hash · votes · nonce',
    C['lgrey'], C['chain'], fs=8)

box(ax, 0.55, 4.05, 3.7, 0.75, 'VoteRecord',
    'voter_id_hash · enc_vote · zkp_hash · sig',
    C['lgrey'], C['chain'], fs=8)
box(ax, 4.55, 4.05, 3.8, 0.75, 'Merkle Tree (SHA3-256)',
    '0x00 leaf prefix · 0x01 node prefix',
    C['lgrey'], C['chain'], fs=8)

box(ax, 0.55, 2.85, 7.8, 0.85, 'Chain Verification',
    'Hash chain · PoW · ML-DSA-65 authority signatures · Merkle roots',
    C['lgrey'], C['chain'], fs=8.5, bold=True)

epanel = FancyBboxPatch((9.0, 2.6), 8.65, 3.8,
    boxstyle="round,pad=0.1", linewidth=2,
    edgecolor=C['eth'], facecolor=C['lindigo'], zorder=1)
ax.add_patch(epanel)
ax.text(13.32, 6.17, 'ETHEREUM ANCHORING LAYER', ha='center', fontsize=9,
        fontweight='bold', color=C['eth'])

box(ax, 9.25, 5.1, 3.9, 0.75, 'EthBridge',
    'In-memory (eth_tester) or live node',
    C['lindigo'], C['eth'], fs=8.5, bold=True)
box(ax, 13.45, 5.1, 3.9, 0.75, 'VotingLedger.sol',
    'Solidity 0.8.20 smart contract',
    C['lindigo'], C['eth'], fs=8.5, bold=True)

box(ax, 9.25, 4.05, 3.9, 0.75, 'anchor_vote()',
    'nullifier · encVoteHash · zkpHash',
    C['lindigo'], C['eth'], fs=8)
box(ax, 13.45, 4.05, 3.9, 0.75, 'record_batch()',
    'Merkle root of PQ-blockchain block',
    C['lindigo'], C['eth'], fs=8)

box(ax, 9.25, 2.85, 8.1, 0.85, 'finalize_election()',
    'resultsHash · ML-DSA-65 signature → on-chain immutable record',
    C['lindigo'], C['eth'], fs=8.5, bold=True)

# ══════════════════════════════════════════════════════════════════════════════
# ROW 3 — Crypto Primitives footer
# ══════════════════════════════════════════════════════════════════════════════
cpanel = FancyBboxPatch((0.3, 0.2), 17.4, 2.1,
    boxstyle="round,pad=0.1", linewidth=2,
    edgecolor=C['crypto'], facecolor=C['lpurple'], zorder=1)
ax.add_patch(cpanel)
ax.text(9.0, 2.08, 'CRYPTOGRAPHIC FOUNDATION (NIST PQC)', ha='center',
        fontsize=9, fontweight='bold', color=C['crypto'])

prims = [
    ('ML-KEM-768\n(FIPS 203)', 'Key Encapsulation\nHybrid encryption', C['crypto']),
    ('ML-DSA-65\n(FIPS 204)', 'Digital Signatures\nVotes & blocks', C['crypto']),
    ('BFV / TenSEAL', 'Fully Homomorphic\nEncryption (FHE)', C['fhe']),
    ('Ajtai + Sigma\nZKP', 'Range Proofs\n(vote validity)', C['zkp']),
    ('AES-256-GCM\nSHA3 / SHAKE256', 'Symmetric Enc.\nHashing & KDF', '#795548'),
    ('BioHashing\n(Gabor+HOG)', 'Cancellable\nBiometrics', C['bio']),
]
xpos = [0.55, 3.45, 6.35, 9.25, 12.15, 15.0]
for (name, desc, col), xp in zip(prims, xpos):
    box(ax, xp, 0.38, 2.65, 1.45, name, desc, '#FFFFFF', col, fs=8.5, bold=True)

# ══════════════════════════════════════════════════════════════════════════════
# ARROWS (inter-panel)
# ══════════════════════════════════════════════════════════════════════════════
# Voter → Authority (ballot submission)
arrow(ax, 4.15, 9.0, 4.55, 9.0, C['voter'], lw=2,
      label='Vote Submission')
# Authority → Blockchain
arrow(ax, 7.0, 7.0, 5.5, 6.42, C['auth'], lw=1.8,
      label='VoteRecord')
# Blockchain → Eth
arrow(ax, 8.6, 4.45, 9.25, 4.45, C['chain'], lw=1.8,
      label='anchor / batch')
# Authority → Eth (finalize)
arrow(ax, 9.0, 7.0, 13.32, 6.42, C['eth'], lw=1.5,
      label='finalize_election()')
# Crypto footer ↑ to panels
for xp in [1.87, 4.77, 7.67, 10.57]:
    ax.annotate('', xy=(xp, 2.6), xytext=(xp, 2.3),
                arrowprops=dict(arrowstyle='->', color=C['crypto'],
                                lw=1.2, alpha=0.6))

# ══════════════════════════════════════════════════════════════════════════════
# Legend
# ══════════════════════════════════════════════════════════════════════════════
legend_items = [
    mpatches.Patch(facecolor=C['lblue'], edgecolor=C['voter'], label='Voter Client'),
    mpatches.Patch(facecolor=C['lgreen'], edgecolor=C['auth'], label='Election Authority'),
    mpatches.Patch(facecolor=C['lgrey'], edgecolor=C['chain'], label='PQ Blockchain'),
    mpatches.Patch(facecolor=C['lindigo'], edgecolor=C['eth'], label='Ethereum Layer'),
    mpatches.Patch(facecolor=C['lpurple'], edgecolor=C['crypto'], label='Crypto Primitives'),
]
ax.legend(handles=legend_items, loc='upper right', bbox_to_anchor=(0.995, 0.985),
          fontsize=8, framealpha=0.9, ncol=1)

plt.tight_layout(pad=0.3)
plt.savefig('/home/user/RE-code/diagrams/fig1_system_architecture.png',
            dpi=200, bbox_inches='tight', facecolor='#F8F9FA')
plt.close()
print("Fig 1 saved.")
