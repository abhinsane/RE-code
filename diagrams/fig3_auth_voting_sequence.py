"""
Figure 3: Authentication & Ballot Casting — Sequence Diagram (UML-style)
"""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

fig, ax = plt.subplots(figsize=(18, 13))
ax.set_xlim(0, 18)
ax.set_ylim(0, 13)
ax.axis('off')
fig.patch.set_facecolor('#FAFAFA')

C = {
    'voter':  '#1565C0',
    'auth':   '#2E7D32',
    'bio':    '#00838F',
    'fhe':    '#BF360C',
    'zkp':    '#E65100',
    'chain':  '#4527A0',
    'eth':    '#283593',
    'line':   '#90A4AE',
    'msg':    '#37474F',
    'title':  '#1A237E',
    'phase':  '#F5F5F5',
    'phase_b':'#ECEFF1',
}

# ── Title ─────────────────────────────────────────────────────────────────────
ax.text(9, 12.6, 'Authentication & Ballot Casting — Protocol Sequence',
        ha='center', fontsize=14, fontweight='bold', color=C['title'])
ax.plot([0.3, 17.7], [12.35, 12.35], color=C['title'], lw=1.5)

# ══════════════════════════════════════════════════════════════════════════════
# LIFELINE ACTORS
# ══════════════════════════════════════════════════════════════════════════════
actors = [
    (1.1,  'Voter\nClient',     C['voter']),
    (4.0,  'Election\nAuthority', C['auth']),
    (6.9,  'Biometric\nProcessor', C['bio']),
    (9.8,  'FHE\nAuthority',    C['fhe']),
    (12.7, 'ZKP\nVerifier',     C['zkp']),
    (15.6, 'Blockchain\n+ Eth', C['chain']),
]
LIFEY_TOP = 11.85
LIFEY_BOT = 0.35
actor_x = [a[0] for a in actors]

for ax_x, lbl, col in actors:
    b = FancyBboxPatch((ax_x-0.7, LIFEY_TOP-0.45), 1.4, 0.7,
                       boxstyle="round,pad=0.06", linewidth=2,
                       edgecolor=col, facecolor=col, alpha=0.9, zorder=4)
    ax.add_patch(b)
    ax.text(ax_x, LIFEY_TOP-0.1, lbl, ha='center', va='center',
            fontsize=8, fontweight='bold', color='white', zorder=5)
    ax.plot([ax_x, ax_x], [LIFEY_TOP-0.45, LIFEY_BOT],
            color=C['line'], lw=1.2, ls='--', zorder=2)

# ── helpers ───────────────────────────────────────────────────────────────────
def msg(ax, x1, x2, y, label, col='#37474F', dashed=False, ret=False):
    ls = '--' if dashed else '-'
    style = '<-' if ret else '->'
    ax.annotate('', xy=(x2, y), xytext=(x1, y),
                arrowprops=dict(arrowstyle=style, color=col,
                                lw=1.4, linestyle=ls))
    mx = (x1+x2)/2
    off = 0.1
    ax.text(mx, y+off, label, ha='center', va='bottom',
            fontsize=7.5, color=col, style='italic' if ret else 'normal')

def activation(ax, x, y_top, y_bot, col):
    rect = FancyBboxPatch((x-0.12, y_bot), 0.24, y_top-y_bot,
                          boxstyle="square,pad=0", linewidth=1.2,
                          edgecolor=col, facecolor=col, alpha=0.35, zorder=3)
    ax.add_patch(rect)

def phase_band(ax, y_top, y_bot, label, col, lc):
    rect = FancyBboxPatch((0.05, y_bot), 17.9, y_top-y_bot,
                          boxstyle="square,pad=0", linewidth=1,
                          edgecolor=lc, facecolor=col, alpha=0.22, zorder=1)
    ax.add_patch(rect)
    ax.text(0.18, (y_top+y_bot)/2, label, ha='left', va='center',
            fontsize=8, fontweight='bold', color=lc,
            rotation=90, alpha=0.8)

# ══════════════════════════════════════════════════════════════════════════════
# PHASE A — AUTHENTICATION  (y: 11.3 → 8.2)
# ══════════════════════════════════════════════════════════════════════════════
phase_band(ax, 11.4, 8.1, 'PHASE A\nAUTHEN-\nTICATION',
           '#E3F2FD', C['voter'])

y = 11.0
activation(ax, actor_x[0], y+0.3, y-0.3, C['voter'])
msg(ax, actor_x[0], actor_x[1], y,
    'authenticate(voter_id, fingerprint, PIN)', C['voter'])

y -= 0.55
activation(ax, actor_x[1], y+0.3, y-2.5, C['auth'])
msg(ax, actor_x[1], actor_x[2], y,
    'Check lockout status · Pass to BioProcessor', C['auth'])

y -= 0.55
activation(ax, actor_x[2], y+0.3, y-1.55, C['bio'])
msg(ax, actor_x[2], actor_x[2]-0.5, y,  # self-call
    'CLAHE → Gabor(48 filters) → HOG(8100-d)', C['bio'])

y -= 0.55
msg(ax, actor_x[2], actor_x[2]-0.5, y,
    'SHAKE256(PIN) → orthogonal matrix → BioHash', C['bio'])

y -= 0.55
msg(ax, actor_x[1], actor_x[2], y,
    'ML-KEM-768 decrypt stored template', C['bio'])
msg(ax, actor_x[2], actor_x[1], y-0.28,
    '← live_biohash vs stored_biohash', C['bio'], ret=True)

y -= 0.9
ax.text((actor_x[1]+actor_x[2])/2, y+0.08,
        'Hamming similarity ≥ 0.80?', ha='center', fontsize=8,
        color='#F57F17', fontweight='bold')
# diamond inline
cx, cy = (actor_x[1]+actor_x[2])/2, y-0.22
dxs = [cx, cx+0.45, cx, cx-0.45, cx]
dys = [cy+0.22, cy, cy-0.22, cy, cy+0.22]
ax.fill(dxs, dys, fc='#FFF9C4', ec='#F57F17', lw=1.5, zorder=3)

y -= 0.7
msg(ax, actor_x[1], actor_x[0], y,
    '← Grant session token (10 min) / REJECT + lockout', C['auth'], ret=True)

# ══════════════════════════════════════════════════════════════════════════════
# PHASE B — BALLOT PREPARATION  (y: 8.0 → 5.5)
# ══════════════════════════════════════════════════════════════════════════════
phase_band(ax, 8.0, 5.4, 'PHASE B\nBALLOT\nPREP', '#FFF8E1', C['fhe'])

y = 7.7
msg(ax, actor_x[0], actor_x[3], y,
    'FHEVoter.encrypt_vote(candidate_idx)', C['fhe'])
activation(ax, actor_x[3], y+0.3, y-0.7, C['fhe'])
y -= 0.45
msg(ax, actor_x[3], actor_x[0], y,
    '← BFV one-hot ciphertext (enc_vote_bytes)', C['fhe'], ret=True)

y -= 0.65
msg(ax, actor_x[0], actor_x[4], y,
    'LatticeZKP.prove_vote_range(vote, context)', C['zkp'])
activation(ax, actor_x[4], y+0.3, y-0.85, C['zkp'])
y -= 0.4
msg(ax, actor_x[4], actor_x[4]+0.3, y,
    'Ajtai commit · Sigma proof · CDS OR proofs', C['zkp'])
y -= 0.35
msg(ax, actor_x[4], actor_x[0], y,
    '← zkp_proof (NO plaintext vote)', C['zkp'], ret=True)

y -= 0.55
msg(ax, actor_x[0], actor_x[0]+0.3, y,
    'ML-DSA-65.sign(enc_vote_hex ‖ zkp_hash)', C['voter'])

# ══════════════════════════════════════════════════════════════════════════════
# PHASE C — VOTE SUBMISSION & VALIDATION  (y: 5.4 → 2.8)
# ══════════════════════════════════════════════════════════════════════════════
phase_band(ax, 5.4, 2.7, 'PHASE C\nSUBMIT &\nVALIDATE', '#E8F5E9', C['auth'])

y = 5.1
msg(ax, actor_x[0], actor_x[1], y,
    'VoteSubmission {voter_id, enc_vote, zkp, sig}', C['voter'])
activation(ax, actor_x[1], y+0.3, y-2.1, C['auth'])

y -= 0.45
msg(ax, actor_x[1], actor_x[1]+0.3, y,
    '① Check: registered · active · session valid · not voted', C['auth'])

y -= 0.42
msg(ax, actor_x[1], actor_x[1]+0.3, y,
    '② ML-DSA-65.verify(sig, enc_vote_hex ‖ zkp_hash)', C['auth'])

y -= 0.42
msg(ax, actor_x[1], actor_x[4], y,
    '③ ZKP verify_vote_proof(proof, context)', C['zkp'])
activation(ax, actor_x[4], y+0.2, y-0.3, C['zkp'])
y -= 0.3
msg(ax, actor_x[4], actor_x[1], y,
    '← valid / invalid', C['zkp'], ret=True)

y -= 0.4
msg(ax, actor_x[1], actor_x[3], y,
    '④ FHETally.add_encrypted_vote(ciphertext)', C['fhe'])
activation(ax, actor_x[3], y+0.2, y-0.2, C['fhe'])

y -= 0.4
msg(ax, actor_x[1], actor_x[5], y,
    '⑤ Blockchain.add_vote(VoteRecord) + Eth.anchor_vote()', C['chain'])
activation(ax, actor_x[5], y+0.2, y-0.35, C['chain'])

y -= 0.38
msg(ax, actor_x[1], actor_x[1]+0.3, y,
    '⑥ Mark voter as has_voted=True · clear session token', C['auth'])

y -= 0.35
msg(ax, actor_x[1], actor_x[0], y,
    '← VoteAccepted (blockchain tx ref)', C['auth'], ret=True)

# ══════════════════════════════════════════════════════════════════════════════
# PHASE D — TALLYING  (y: 2.7 → 0.4)
# ══════════════════════════════════════════════════════════════════════════════
phase_band(ax, 2.7, 0.3, 'PHASE D\nTALLY', '#EDE7F6', C['chain'])

y = 2.4
msg(ax, actor_x[1], actor_x[5], y,
    'mine_pending_votes() → PoW + ML-DSA-65 block sign', C['chain'])
activation(ax, actor_x[5], y+0.2, y-0.35, C['chain'])

y -= 0.5
msg(ax, actor_x[1], actor_x[3], y,
    'FHEAuthority.decrypt_tally() — ONE decryption', C['fhe'])
activation(ax, actor_x[3], y+0.2, y-0.3, C['fhe'])
y -= 0.32
msg(ax, actor_x[3], actor_x[1], y,
    '← [count_cand0, count_cand1, …] (sum = N)', C['fhe'], ret=True)

y -= 0.4
msg(ax, actor_x[1], actor_x[5], y,
    'EthBridge.finalize_election(resultsHash, ML-DSA-65 sig)', C['chain'])

y -= 0.35
msg(ax, actor_x[1], actor_x[0], y,
    '← Signed results package (publicly verifiable)', C['auth'], ret=True)

# ── Legend ────────────────────────────────────────────────────────────────────
import matplotlib.patches as mpatches
items = [
    mpatches.Patch(fc='#E3F2FD', ec=C['voter'],  label='Phase A: Authentication'),
    mpatches.Patch(fc='#FFF8E1', ec=C['fhe'],    label='Phase B: Ballot Preparation'),
    mpatches.Patch(fc='#E8F5E9', ec=C['auth'],   label='Phase C: Submit & Validate'),
    mpatches.Patch(fc='#EDE7F6', ec=C['chain'],  label='Phase D: Tally & Finalize'),
]
ax.legend(handles=items, loc='lower right', bbox_to_anchor=(0.99, 0.01),
          fontsize=8, framealpha=0.92, ncol=2)

plt.tight_layout(pad=0.3)
plt.savefig('/home/user/RE-code/diagrams/fig3_auth_voting_sequence.png',
            dpi=200, bbox_inches='tight', facecolor='#FAFAFA')
plt.close()
print("Fig 3 saved.")
