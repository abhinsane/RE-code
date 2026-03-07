"""
Figure 5: Blockchain Structure + Ethereum Anchoring
"""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
import matplotlib.patches as mpatches

fig, ax = plt.subplots(figsize=(18, 11))
ax.set_xlim(0, 18)
ax.set_ylim(0, 11)
ax.axis('off')
fig.patch.set_facecolor('#FAFAFA')

C = {
    'genesis': '#1A237E',
    'block':   '#1565C0',
    'merkle':  '#2E7D32',
    'vote':    '#E65100',
    'eth':     '#283593',
    'sig':     '#6A1B9A',
    'bg_block':'#E3F2FD',
    'bg_merkle':'#E8F5E9',
    'bg_vote': '#FFF3E0',
    'bg_eth':  '#E8EAF6',
    'chain':   '#455A64',
}

ax.text(9, 10.6, 'PQ Blockchain Structure & Ethereum Anchoring Layer',
        ha='center', fontsize=14, fontweight='bold', color=C['genesis'])
ax.plot([0.3, 17.7], [10.35, 10.35], color=C['genesis'], lw=1.5)

def fbox(ax, x, y, w, h, title, lines, fc, ec, tfs=8.5, bfs=7.5):
    rect = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.07",
                          linewidth=1.8, edgecolor=ec, facecolor=fc, zorder=3)
    ax.add_patch(rect)
    ax.text(x+w/2, y+h-0.18, title, ha='center', va='top',
            fontsize=tfs, fontweight='bold', color=ec, zorder=4)
    for i, ln in enumerate(lines):
        ax.text(x+0.15, y+h-0.42-(i*0.3), ln, ha='left', va='top',
                fontsize=bfs, color='#37474F', zorder=4)

def arr(ax, x1, y1, x2, y2, col, lw=2.0, label=None):
    ax.annotate('', xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle='->', color=col, lw=lw))
    if label:
        mx, my = (x1+x2)/2, (y1+y2)/2
        ax.text(mx, my+0.12, label, ha='center', va='bottom',
                fontsize=7.5, color=col)

# ══════════════════════════════════════════════════════════════════════════════
# BLOCK CHAIN ROW (y: 7.3 → 10.2)
# ══════════════════════════════════════════════════════════════════════════════
blocks = [
    (0.2,  'Genesis Block\n(index=0)',    '#D1C4E9', C['genesis']),
    (4.5,  'Block i  (index=i)',          C['bg_block'], C['block']),
    (9.3,  'Block i+1  (index=i+1)',      C['bg_block'], C['block']),
    (14.1, 'Block N  (final)',            '#E8F5E9', C['merkle']),
]
block_w = 3.9
block_h = 2.7

for bx, btitle, bfc, bec in blocks:
    rect = FancyBboxPatch((bx, 7.4), block_w, block_h,
                          boxstyle="round,pad=0.08", linewidth=2.2,
                          edgecolor=bec, facecolor=bfc, zorder=3)
    ax.add_patch(rect)
    ax.text(bx+block_w/2, 7.4+block_h-0.18, btitle,
            ha='center', va='top', fontsize=8.5, fontweight='bold', color=bec)
    fields = [
        'index:      int',
        'timestamp:  Unix float',
        'prev_hash:  SHA3(prev block)',
        'merkle_root: SHA3 Merkle root',
        'nonce:      PoW nonce',
        'hash:       SHA3(header)',
        'sig:        ML-DSA-65(hash‖root)',
    ]
    for i, f in enumerate(fields):
        ax.text(bx+0.18, 7.4+block_h-0.46-i*0.3, f, ha='left', va='top',
                fontsize=6.8, color='#37474F', zorder=4)

# Arrows between blocks
for bx in [0.2+block_w, 4.5+block_w, 9.3+block_w]:
    arr(ax, bx+0.05, 7.4+block_h/2, bx+0.75, 7.4+block_h/2,
        C['chain'], lw=2.5, label='prev_hash')

# ellipsis between block i+1 and N
ax.text(13.25, 7.4+block_h/2, '···', ha='center', fontsize=14,
        color=C['chain'], fontweight='bold')

# ══════════════════════════════════════════════════════════════════════════════
# MERKLE TREE (below block i) — y: 3.8 → 7.3
# ══════════════════════════════════════════════════════════════════════════════
ax.text(6.45, 7.2, 'Merkle Tree Detail  (for Block i)',
        ha='center', fontsize=9, fontweight='bold', color=C['merkle'])
ax.plot([0.2, 12.6], [7.0, 7.0], color=C['merkle'], lw=1, ls='--', alpha=0.5)

# Root node
fbox(ax, 4.7, 6.15, 3.5, 0.65,
     'Merkle Root', ['SHA3(0x01 ‖ H_L ‖ H_R)'],
     C['bg_merkle'], C['merkle'])
# Level 1 nodes
fbox(ax, 1.5, 5.05, 3.3, 0.65,
     'H_L', ['SHA3(0x01 ‖ H_LL ‖ H_LR)'],
     C['bg_merkle'], C['merkle'])
fbox(ax, 8.1, 5.05, 3.3, 0.65,
     'H_R', ['SHA3(0x01 ‖ H_RL ‖ H_RR)'],
     C['bg_merkle'], C['merkle'])
# Leaf nodes
leaves = [
    (0.2,  'Leaf 0',    'SHA3(0x00 ‖ VoteRecord₀)'),
    (2.7,  'Leaf 1',    'SHA3(0x00 ‖ VoteRecord₁)'),
    (6.8,  'Leaf 2',    'SHA3(0x00 ‖ VoteRecord₂)'),
    (9.3,  'Leaf 3',    'SHA3(0x00 ‖ VoteRecord₃)'),
]
for lx, lname, lsub in leaves:
    fbox(ax, lx, 3.85, 2.3, 0.7, lname, [lsub],
         '#FFF8E1', C['vote'], tfs=8, bfs=6.5)

# Merkle arrows
arr(ax, 6.45, 6.15, 4.85, 5.7, C['merkle'], lw=1.5)   # root → HL
arr(ax, 6.45, 6.15, 8.1+1.65, 5.7, C['merkle'], lw=1.5) # root → HR
arr(ax, 3.15, 5.05, 1.35, 4.55, C['merkle'], lw=1.3)
arr(ax, 3.15, 5.05, 3.0+0.35, 4.55, C['merkle'], lw=1.3)
arr(ax, 9.75, 5.05, 7.0+0.15, 4.55, C['merkle'], lw=1.3)
arr(ax, 9.75, 5.05, 9.3+1.15, 4.55, C['merkle'], lw=1.3)

# Dashed connector from block to merkle root
ax.annotate('', xy=(6.45, 6.8), xytext=(6.45, 7.4),
            arrowprops=dict(arrowstyle='->', color=C['merkle'],
                            lw=1.5, linestyle='dashed'))

# ══════════════════════════════════════════════════════════════════════════════
# VOTE RECORD DETAIL  (right side, y: 3.8 → 7.2)
# ══════════════════════════════════════════════════════════════════════════════
ax.text(15.0, 7.2, 'VoteRecord Schema',
        ha='center', fontsize=9, fontweight='bold', color=C['vote'])
fbox(ax, 12.8, 3.85, 4.8, 3.2,
     'VoteRecord',
     [
         'voter_id_hash:   SHA3(voter_id)',
         'encrypted_vote:  hex(BFV ciphertext)',
         'zkp_commitment:  hex(first 32 ZKP elems)',
         'zkp_proof_hash:  SHA3(zkp_proof_JSON)',
         'signature:       ML-DSA-65(enc‖zkp_hash)',
         'voter_sig_pk:    voter ML-DSA-65 public key',
         'timestamp:       Unix float',
         '——————————————————————',
         'Serialized as JSON (sorted keys)',
         'for deterministic Merkle hashing',
     ],
     C['bg_vote'], C['vote'], tfs=8.5, bfs=7)

# ══════════════════════════════════════════════════════════════════════════════
# ETHEREUM LAYER  (y: 0.3 → 3.7)
# ══════════════════════════════════════════════════════════════════════════════
ax.text(9, 3.6, 'Ethereum Anchoring Layer  (VotingLedger.sol)',
        ha='center', fontsize=9, fontweight='bold', color=C['eth'])
ax.plot([0.2, 17.8], [3.4, 3.4], color=C['eth'], lw=1.2, ls='--')

eth_items = [
    (0.2,   'anchor_vote()',
     ['nullifier = SHA3(voter_id_hash)',
      'encVoteHash = SHA3(ciphertext)',
      'zkpHash = SHA3(zkp_proof)',
      'Stored: bytes32 × 3 + timestamp'],
     C['bg_eth'], C['eth']),
    (4.7,   'record_batch()',
     ['merkleRoot = PQ-block Merkle root',
      'vote_count = votes in block',
      'Event: BatchRecorded',
      'Links PQ-chain to Ethereum'],
     C['bg_eth'], C['eth']),
    (9.2,   'finalize_election()',
     ['resultsHash = SHA3(JSON results)',
      'pqSig = ML-DSA-65(resultsHash)',
      'Closes election (no more votes)',
      'Event: ElectionFinalized'],
     C['bg_eth'], C['eth']),
    (13.7,  'Nullifier Check',
     ['mapping(bytes32→bool)',
      'Prevents double-vote on-chain',
      'Double-hash: SHA3(SHA3(voter_id))',
      'Immutable after anchorVote()'],
     '#FBE9E7', '#BF360C'),
]
for ex, etitle, elines, efc, eec in eth_items:
    fbox(ax, ex, 0.35, 4.2, 2.85,
         etitle, elines, efc, eec, tfs=8.5, bfs=7.3)

# Arrows from blockchain to Eth layer
arr(ax, 4.5+block_w/2, 7.4, 2.3, 3.2, C['eth'], lw=1.5, label='per vote')
arr(ax, 9.3+block_w/2, 7.4, 6.8, 3.2, C['eth'], lw=1.5, label='per block')
arr(ax, 14.1+block_w/2, 7.4, 11.3, 3.2, C['eth'], lw=1.5, label='finalize')

# Legend
items = [
    mpatches.Patch(fc=C['bg_block'], ec=C['block'], label='Blockchain Block'),
    mpatches.Patch(fc=C['bg_merkle'], ec=C['merkle'], label='Merkle Tree Node'),
    mpatches.Patch(fc=C['bg_vote'], ec=C['vote'], label='Vote Record'),
    mpatches.Patch(fc=C['bg_eth'], ec=C['eth'], label='Ethereum Layer'),
]
ax.legend(handles=items, loc='lower left', bbox_to_anchor=(0.01, 0.01),
          fontsize=8.5, framealpha=0.92)

plt.tight_layout(pad=0.3)
plt.savefig('/home/user/RE-code/diagrams/fig5_blockchain_structure.png',
            dpi=200, bbox_inches='tight', facecolor='#FAFAFA')
plt.close()
print("Fig 5 saved.")
