"""
Figure 7: Cancellable Biometric Pipeline
"""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
import matplotlib.patches as mpatches
import numpy as np

fig, ax = plt.subplots(figsize=(18, 8))
ax.set_xlim(0, 18)
ax.set_ylim(0, 8)
ax.axis('off')
fig.patch.set_facecolor('#FAFAFA')

C = {
    'input':   '#1565C0',
    'preproc': '#00838F',
    'feat':    '#2E7D32',
    'bio':     '#6A1B9A',
    'enc':     '#BF360C',
    'store':   '#E65100',
    'match':   '#283593',
    'bg_in':   '#E3F2FD',
    'bg_pre':  '#E0F7FA',
    'bg_feat': '#E8F5E9',
    'bg_bio':  '#F3E5F5',
    'bg_enc':  '#FBE9E7',
    'bg_st':   '#FFF3E0',
    'bg_mtch': '#E8EAF6',
    'title':   '#1A237E',
}

ax.text(9, 7.6, 'Cancellable Biometric Pipeline — Enrollment & Verification',
        ha='center', fontsize=13, fontweight='bold', color=C['title'])
ax.plot([0.3, 17.7], [7.35, 7.35], color=C['title'], lw=1.5)

def stage(ax, x, y, w, h, title, lines, fc, ec, fs=8.5, lfs=7.5):
    rect = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.08",
                          linewidth=2, edgecolor=ec, facecolor=fc, zorder=3)
    ax.add_patch(rect)
    ax.text(x+w/2, y+h-0.2, title, ha='center', va='top',
            fontsize=fs, fontweight='bold', color=ec, zorder=4)
    for i, ln in enumerate(lines):
        ax.text(x+0.18, y+h-0.52-i*0.34, '▸ '+ln, ha='left', va='top',
                fontsize=lfs, color='#37474F', zorder=4)

def arr(ax, x1, y1, x2, y2, col, lw=1.8, label=None):
    ax.annotate('', xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle='->', color=col, lw=lw))
    if label:
        mx, my = (x1+x2)/2, (y1+y2)/2+0.08
        ax.text(mx, my, label, ha='center', va='bottom',
                fontsize=7.2, color=col, style='italic')

# ══════════════════════════════════════════════════════════════════════════════
# ENROLLMENT PATH (top row, y: 4.2 → 7.1)
# ══════════════════════════════════════════════════════════════════════════════
ax.text(9, 7.12, '── ENROLLMENT PATH ──', ha='center', fontsize=8.5,
        color='#455A64', style='italic')

stage(ax, 0.2, 4.35, 2.5, 2.55,
    'INPUT',
    ['Fingerprint image (BMP/PNG)',
     'SOCOFing dataset or synthetic',
     'User PIN / token (secret)',
     'voter_id (unique)'],
    C['bg_in'], C['input'])

stage(ax, 3.05, 4.35, 2.9, 2.55,
    'PRE-PROCESSING',
    ['Load grayscale image',
     'Resize to 256×256',
     'CLAHE enhancement',
     '(ridge contrast boost)'],
    C['bg_pre'], C['preproc'])

stage(ax, 6.25, 4.35, 3.2, 2.55,
    'FEATURE EXTRACTION',
    ['Gabor filter bank:',
     '  λ={6,9,12}px × 16 orient.',
     '  → 48 filter responses',
     'HOG descriptor: 8100-d',
     'L2-normalise → feat. vec.'],
    C['bg_feat'], C['feat'])

stage(ax, 9.75, 4.35, 3.2, 2.55,
    'BIOHASHING (ISO/IEC 24745)',
    ['SHAKE256(PIN) → 256-bit seed',
     'Seed → rand orthogonal matrix',
     '  P ∈ R^(512 × 8100)',
     'Project: h = P · feat',
     'Binarise at median → 512-bit'],
    C['bg_bio'], C['bio'])

stage(ax, 13.25, 4.35, 2.5, 2.55,
    'PQ ENCRYPTION',
    ['ML-KEM-768 encapsulate',
     'Shared secret → AES-256-GCM',
     'Encrypt 512-bit BioHash',
     'Store: enc_template + ct'],
    C['bg_enc'], C['enc'])

stage(ax, 16.05, 4.35, 1.8, 2.55,
    'STORAGE',
    ['enc_template',
     'token_hash',
     'feature_dim',
     'voter_id_hash'],
    C['bg_st'], C['store'])

# Enrollment arrows
arr(ax, 2.7, 5.625, 3.05, 5.625, C['input'], label='raw image\n+ PIN')
arr(ax, 5.95, 5.625, 6.25, 5.625, C['preproc'], label='enhanced\nimage')
arr(ax, 9.45, 5.625, 9.75, 5.625, C['feat'], label='feat vec\n8100-d')
arr(ax, 12.95, 5.625, 13.25, 5.625, C['bio'], label='512-bit\nBioHash')
arr(ax, 15.75, 5.625, 16.05, 5.625, C['enc'], label='encrypted\ntemplate')

# ══════════════════════════════════════════════════════════════════════════════
# VERIFICATION PATH (bottom row, y: 0.4 → 4.0)
# ══════════════════════════════════════════════════════════════════════════════
ax.plot([0.2, 17.85], [4.1, 4.1], color='#CFD8DC', lw=1.5, ls='--')
ax.text(9, 3.95, '── VERIFICATION PATH ──', ha='center', fontsize=8.5,
        color='#455A64', style='italic')

stage(ax, 0.2, 0.55, 2.5, 3.2,
    'LIVE INPUT',
    ['Live fingerprint scan',
     'Same user PIN',
     'voter_id to look up'],
    C['bg_in'], C['input'])

stage(ax, 3.05, 0.55, 2.9, 3.2,
    'PRE-PROC + EXTRACT',
    ['CLAHE → 256×256',
     'Gabor bank (48 filters)',
     'HOG descriptor: 8100-d',
     'L2-normalise'],
    C['bg_pre'], C['preproc'])

stage(ax, 6.25, 0.55, 3.2, 3.2,
    'LIVE BIOHASH',
    ['SHAKE256(same PIN) → seed',
     'Same orthogonal matrix P',
     '  (derived from same seed)',
     'Project + binarise',
     '→ live_biohash (512-bit)'],
    C['bg_bio'], C['bio'])

stage(ax, 9.75, 0.55, 3.0, 3.2,
    'DECRYPT TEMPLATE',
    ['Retrieve enc_template',
     'ML-KEM-768 decapsulate',
     '  (authority secret key)',
     'AES-256-GCM decrypt',
     '→ stored_biohash'],
    C['bg_enc'], C['enc'])

stage(ax, 13.05, 0.55, 3.2, 3.2,
    'HAMMING MATCH',
    ['Similarity = 1 − (Hamming',
     '  distance / 512)',
     'Threshold: ≥ 0.80',
     'PASS: grant session token',
     'FAIL: increment counter',
     '  ≥5 fails → 5-min lockout'],
    C['bg_mtch'], C['match'])

stage(ax, 16.55, 0.55, 1.3, 3.2,
    'OUT',
    ['PASS /\nFAIL',
     'session\ntoken',
     '10 min'],
    C['bg_st'], C['store'])

# Verification arrows
arr(ax, 2.7, 2.15, 3.05, 2.15, C['input'], label='raw + PIN')
arr(ax, 5.95, 2.15, 6.25, 2.15, C['preproc'], label='feat 8100-d')
arr(ax, 9.45, 2.15, 9.75, 2.15, C['bio'], label='live hash')
arr(ax, 12.75, 2.15, 13.05, 2.15, C['enc'], label='stored hash')
arr(ax, 16.25, 2.15, 16.55, 2.15, C['match'])

# Cross-path arrow: decrypt template coming from storage
ax.annotate('', xy=(12.75, 2.15), xytext=(16.95, 4.35),
            arrowprops=dict(arrowstyle='->', color=C['store'],
                            lw=1.5, linestyle='dashed',
                            connectionstyle='arc3,rad=0.15'))
ax.text(15.5, 3.5, 'look up\nenc_template', ha='center', fontsize=7,
        color=C['store'], style='italic')

# Cancelability note
cancel_rect = FancyBboxPatch((0.2, 0.2), 17.6, 0.25,
                              boxstyle="round,pad=0.05", linewidth=1.2,
                              edgecolor='#F57F17', facecolor='#FFFDE7', zorder=3)
ax.add_patch(cancel_rect)
ax.text(9, 0.325, ('Cancelability: new PIN → new SHAKE256 seed → '
                   'new orthogonal matrix → new BioHash subspace. '
                   'Old template CANNOT be linked to new. Revoke by replacing encrypted template.'),
        ha='center', va='center', fontsize=7.5, color='#E65100', zorder=4)

plt.tight_layout(pad=0.3)
plt.savefig('/home/user/RE-code/diagrams/fig7_biometric_pipeline.png',
            dpi=200, bbox_inches='tight', facecolor='#FAFAFA')
plt.close()
print("Fig 7 saved.")
