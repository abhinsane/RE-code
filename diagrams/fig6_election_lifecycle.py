"""
Figure 6: End-to-End Election Lifecycle
"""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import matplotlib.patches as mpatches
import numpy as np

fig, ax = plt.subplots(figsize=(18, 9))
ax.set_xlim(0, 18)
ax.set_ylim(0, 9)
ax.axis('off')
fig.patch.set_facecolor('#F5F5F5')

C = {
    'p1': '#1565C0',  # Phase 1 Setup
    'p2': '#2E7D32',  # Phase 2 Registration
    'p3': '#00838F',  # Phase 3 Authentication
    'p4': '#E65100',  # Phase 4 Voting
    'p5': '#6A1B9A',  # Phase 5 Tallying
    'p6': '#283593',  # Phase 6 Publication
    'bg1': '#E3F2FD',
    'bg2': '#E8F5E9',
    'bg3': '#E0F7FA',
    'bg4': '#FBE9E7',
    'bg5': '#F3E5F5',
    'bg6': '#E8EAF6',
    'title': '#1A237E',
}

ax.text(9, 8.6, 'End-to-End Election Lifecycle',
        ha='center', fontsize=14, fontweight='bold', color=C['title'])
ax.plot([0.3, 17.7], [8.35, 8.35], color=C['title'], lw=1.5)

# ── Phase timeline bar ────────────────────────────────────────────────────────
phases = [
    ('Phase 1\nSETUP',          C['p1'], C['bg1']),
    ('Phase 2\nREGISTRATION',   C['p2'], C['bg2']),
    ('Phase 3\nAUTHENTICATION', C['p3'], C['bg3']),
    ('Phase 4\nVOTING',         C['p4'], C['bg4']),
    ('Phase 5\nTALLYING',       C['p5'], C['bg5']),
    ('Phase 6\nPUBLICATION',    C['p6'], C['bg6']),
]
ph_x = np.linspace(0.3, 14.8, 7)
ph_w = ph_x[1] - ph_x[0] - 0.15

for i, (plbl, pec, pfc) in enumerate(phases):
    x = ph_x[i]
    rect = FancyBboxPatch((x, 7.25), ph_w, 0.85,
                          boxstyle="round,pad=0.06", linewidth=2.0,
                          edgecolor=pec, facecolor=pec, zorder=3)
    ax.add_patch(rect)
    ax.text(x+ph_w/2, 7.67, plbl, ha='center', va='center',
            fontsize=7.5, fontweight='bold', color='white', zorder=4)
    if i < len(phases)-1:
        ax.annotate('', xy=(ph_x[i+1]-0.02, 7.67),
                    xytext=(ph_x[i]+ph_w+0.02, 7.67),
                    arrowprops=dict(arrowstyle='->', color='#455A64', lw=2))

# ══════════════════════════════════════════════════════════════════════════════
# PHASE DETAIL CARDS
# ══════════════════════════════════════════════════════════════════════════════
def phase_card(ax, x, y, w, h, title, items, fc, ec, note=None):
    rect = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.08",
                          linewidth=2, edgecolor=ec, facecolor=fc, zorder=3)
    ax.add_patch(rect)
    ax.text(x+w/2, y+h-0.2, title, ha='center', va='top',
            fontsize=9, fontweight='bold', color=ec, zorder=4)
    for j, item in enumerate(items):
        ax.text(x+0.18, y+h-0.5-j*0.37, '▸ '+item, ha='left', va='top',
                fontsize=7.5, color='#37474F', zorder=4)
    if note:
        ax.text(x+w/2, y+0.12, note, ha='center', va='bottom',
                fontsize=7, color=ec, style='italic', zorder=4)

phase_card(ax, 0.3, 3.9, 2.85, 3.15,
    'SETUP',
    ['Generate Authority keys',
     'ML-KEM-768 + ML-DSA-65',
     'Init BFV FHE context',
     'Create genesis block',
     'Deploy VotingLedger.sol'],
    C['bg1'], C['p1'],
    note='One-time / per-election')

phase_card(ax, 3.35, 3.9, 2.85, 3.15,
    'REGISTRATION',
    ['Submit fingerprint + PIN',
     'Gabor+HOG feature extract',
     'BioHash (ISO 24745)',
     'ML-KEM-768 enc template',
     'Store voter_id_hash + keys'],
    C['bg2'], C['p2'],
    note='Offline / pre-election')

phase_card(ax, 6.4, 3.9, 2.85, 3.15,
    'AUTHENTICATION',
    ['Live fingerprint scan',
     'Decrypt stored template',
     'Hamming similarity ≥ 0.80',
     'Grant 10-min session token',
     'Lockout after 5 failures'],
    C['bg3'], C['p3'],
    note='Per voting session')

phase_card(ax, 9.45, 3.9, 2.85, 3.15,
    'VOTING',
    ['BFV encrypt one-hot vote',
     'Ajtai ZKP range proof',
     'ML-DSA-65 sign ballot',
     'Authority: verify sig+ZKP',
     'Add to FHE tally + chain'],
    C['bg4'], C['p4'],
    note='Ballot privacy guaranteed')

phase_card(ax, 12.5, 3.9, 2.85, 3.15,
    'TALLYING',
    ['Mine final block (PoW)',
     'Verify entire chain',
     'ONE FHE decryption',
     'Sum check: Σ = N',
     'ML-DSA-65 sign results'],
    C['bg5'], C['p5'],
    note='Single decryption event')

phase_card(ax, 15.55, 3.9, 2.15, 3.15,
    'PUBLISH',
    ['Results + signature',
     'Eth: finalize_election()',
     'Public verification:',
     '  pq_verify(sig, hash)',
     '  Chain audit'],
    C['bg6'], C['p6'],
    note='Publicly auditable')

# ── Connecting arrows between phases ─────────────────────────────────────────
for bx in [3.15, 6.2, 9.25, 12.3, 15.35]:
    ax.annotate('', xy=(bx+0.2, 5.5), xytext=(bx-0.01, 5.5),
                arrowprops=dict(arrowstyle='->', color='#90A4AE', lw=2))

# ══════════════════════════════════════════════════════════════════════════════
# SECURITY PROPERTIES ROW
# ══════════════════════════════════════════════════════════════════════════════
ax.text(9, 3.65, 'Security Properties Guaranteed at Each Phase',
        ha='center', fontsize=9.5, fontweight='bold', color=C['title'])
ax.plot([0.3, 17.7], [3.45, 3.45], color='#CFD8DC', lw=1.2)

props = [
    ('Quantum\nResistance',   'NIST FIPS 203/204\nML-KEM + ML-DSA',    '#EDE7F6', '#6A1B9A'),
    ('Voter\nAnonymity',      'FHE + ZKP\nno vote revealed',            '#E8F5E9', '#2E7D32'),
    ('Double-Vote\nPrevention','Nullifier registry\nSHA3(voter_id_hash)',  '#FBE9E7', '#BF360C'),
    ('Template\nPrivacy',     'ML-KEM-768 enc\nno raw bio stored',      '#E0F7FA', '#006064'),
    ('Ballot\nIntegrity',     'Merkle tree\nML-DSA-65 signed blocks',   '#E3F2FD', '#1565C0'),
    ('Result\nVerifiability', 'ML-DSA-65 sig\nEthereum anchor',         '#E8EAF6', '#283593'),
    ('Cancelable\nBiometrics','New PIN → new\northogonal space',         '#FFF8E1', '#E65100'),
    ('Brute-Force\nProtect',  '5-attempt lockout\n5-min timeout',       '#FFEBEE', '#C62828'),
]
prop_w = 17.4 / len(props)
for i, (ptitle, pdesc, pfc, pec) in enumerate(props):
    x = 0.3 + i * prop_w
    rect = FancyBboxPatch((x+0.05, 0.4), prop_w-0.15, 2.85,
                          boxstyle="round,pad=0.06", linewidth=1.5,
                          edgecolor=pec, facecolor=pfc, zorder=3)
    ax.add_patch(rect)
    ax.text(x+prop_w/2, 0.4+2.85-0.22, ptitle, ha='center', va='top',
            fontsize=8.5, fontweight='bold', color=pec, zorder=4)
    ax.text(x+prop_w/2, 0.4+1.35, pdesc, ha='center', va='center',
            fontsize=7.5, color='#37474F', zorder=4, linespacing=1.4)

# Phase arrows pointing to security props
for i, col in enumerate([C['p1'], C['p2'], C['p3'], C['p4'], C['p5'], C['p6']]):
    sx = 0.3 + (i*1.5 + 0.7) * (17.4/9)
    ax.annotate('', xy=(sx, 3.45), xytext=(ph_x[i]+ph_w/2, 3.9),
                arrowprops=dict(arrowstyle='->', color=col, lw=1.2,
                                linestyle='dotted', alpha=0.6))

plt.tight_layout(pad=0.3)
plt.savefig('/home/user/RE-code/diagrams/fig6_election_lifecycle.png',
            dpi=200, bbox_inches='tight', facecolor='#F5F5F5')
plt.close()
print("Fig 6 saved.")
