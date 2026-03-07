"""
Figure 2: Voter Registration & Biometric Enrollment Flow
"""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

fig, ax = plt.subplots(figsize=(16, 11))
ax.set_xlim(0, 16)
ax.set_ylim(0, 11)
ax.axis('off')
fig.patch.set_facecolor('#FAFAFA')

C = {
    'start':  '#1A237E',
    'input':  '#1565C0',
    'proc':   '#2E7D32',
    'crypto': '#6A1B9A',
    'store':  '#E65100',
    'output': '#00695C',
    'arrow':  '#424242',
    'bg_input':  '#E3F2FD',
    'bg_proc':   '#E8F5E9',
    'bg_crypto': '#F3E5F5',
    'bg_store':  '#FFF3E0',
    'bg_output': '#E0F2F1',
}

def rounded_box(ax, x, y, w, h, text, sub=None, fc='white', ec='black',
                fs=9, bold=False, center_sub=True):
    rect = FancyBboxPatch((x, y), w, h,
                          boxstyle="round,pad=0.08",
                          linewidth=1.6, edgecolor=ec, facecolor=fc, zorder=3)
    ax.add_patch(rect)
    weight = 'bold' if bold else 'normal'
    ty = y + h/2 + (0.15 if sub else 0)
    ax.text(x+w/2, ty, text, ha='center', va='center',
            fontsize=fs, fontweight=weight, color=ec, zorder=4)
    if sub:
        ax.text(x+w/2, y+h/2-0.2, sub, ha='center', va='center',
                fontsize=fs-1.5, color=ec, alpha=0.8, zorder=4)

def diamond(ax, cx, cy, hw, hh, text, fc='white', ec='black', fs=8.5):
    xs = [cx, cx+hw, cx, cx-hw, cx]
    ys = [cy+hh, cy, cy-hh, cy, cy+hh]
    ax.fill(xs, ys, fc=fc, ec=ec, linewidth=1.6, zorder=3)
    ax.text(cx, cy, text, ha='center', va='center',
            fontsize=fs, color=ec, fontweight='bold', zorder=4)

def arr(ax, x1, y1, x2, y2, col='#424242', lw=1.5, label=None):
    ax.annotate('', xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle='->', color=col, lw=lw))
    if label:
        mx, my = (x1+x2)/2, (y1+y2)/2
        ax.text(mx+0.12, my, label, ha='left', va='center',
                fontsize=7.5, color=col)

# ── Title ────────────────────────────────────────────────────────────────────
ax.text(8, 10.6, 'Voter Registration & Biometric Enrollment Protocol',
        ha='center', fontsize=13, fontweight='bold', color=C['start'])
ax.plot([0.5, 15.5], [10.35, 10.35], color=C['start'], lw=1.5)

# ══════════════════════════════════════════════════════════════════════════════
# COLUMN HEADERS  (Voter | Authority | Crypto Layer | Storage)
# ══════════════════════════════════════════════════════════════════════════════
cols = [
    (1.0,  3.0, 'VOTER',           C['input'],  C['bg_input']),
    (4.5,  3.0, 'ELECTION AUTHORITY', C['proc'], C['bg_proc']),
    (8.5,  3.0, 'CRYPTO / BIO LAYER', C['crypto'], C['bg_crypto']),
    (12.5, 2.2, 'SECURE STORAGE',  C['store'], C['bg_store']),
]
for xc, wc, lbl, ec, fc in cols:
    rect = FancyBboxPatch((xc-0.1, 0.2), wc+0.2, 9.9,
                          boxstyle="round,pad=0.1", linewidth=1.5,
                          edgecolor=ec, facecolor=fc, alpha=0.18, zorder=1)
    ax.add_patch(rect)
    ax.text(xc + wc/2, 10.08, lbl, ha='center', fontsize=9,
            fontweight='bold', color=ec)
    ax.plot([xc-0.1, xc+wc+0.1], [9.85, 9.85], color=ec, lw=1, alpha=0.5)

# ══════════════════════════════════════════════════════════════════════════════
# STEP BOXES  (y positions from top downward)
# ══════════════════════════════════════════════════════════════════════════════

# S1 – Start
rounded_box(ax, 1.1, 9.1, 2.8, 0.6, 'START: Submit Registration',
            sub='voter_id + fingerprint + PIN',
            fc=C['bg_input'], ec=C['input'], fs=8.5, bold=True)

# S2 – Authority receives
rounded_box(ax, 4.6, 9.1, 5.8, 0.6, 'Authority receives registration request',
            sub='Validate voter_id uniqueness',
            fc=C['bg_proc'], ec=C['proc'], fs=8.5)

# S3 – Key generation (Voter side)
rounded_box(ax, 1.1, 7.95, 2.8, 0.65,
            'Generate Key Pair',
            sub='ML-KEM-768 + ML-DSA-65',
            fc='#EDE7F6', ec=C['crypto'], fs=8.5)

# S4 – Feature extraction
rounded_box(ax, 8.6, 7.95, 3.2, 0.65,
            'Biometric Feature Extraction',
            sub='CLAHE → Gabor bank (48 filters) → HOG (8100-d)',
            fc='#EDE7F6', ec=C['crypto'], fs=8.2)

# S4b – BioHash
rounded_box(ax, 8.6, 6.85, 3.2, 0.65,
            'BioHashing (ISO/IEC 24745)',
            sub='SHAKE256(PIN) → orthogonal matrix → 512-bit template',
            fc='#EDE7F6', ec=C['crypto'], fs=8.2)

# S5 – ML-KEM encrypt template
rounded_box(ax, 8.6, 5.75, 3.2, 0.65,
            'ML-KEM-768 Hybrid Encryption',
            sub='KEM encapsulate → AES-256-GCM(template)',
            fc='#EDE7F6', ec=C['crypto'], fs=8.2)

# Decision: Duplicate check
diamond(ax, 5.8, 6.5, 1.4, 0.55, 'Voter\nalready\nregistered?',
        fc='#FFF9C4', ec='#F57F17', fs=8)

# S6 – Reject path
rounded_box(ax, 4.6, 4.6, 2.6, 0.6,
            'REJECT',
            sub='Return error to voter',
            fc='#FFEBEE', ec='#C62828', fs=8.5, bold=True)

# S7 – Store to registry
rounded_box(ax, 12.6, 7.95, 2.8, 0.65,
            'VoterRegistration Record',
            sub='voter_id · voter_id_hash',
            fc=C['bg_store'], ec=C['store'], fs=8.2)

rounded_box(ax, 12.6, 6.85, 2.8, 0.65,
            'Public Keys Stored',
            sub='kem_pk · sig_pk',
            fc=C['bg_store'], ec=C['store'], fs=8.2)

rounded_box(ax, 12.6, 5.75, 2.8, 0.65,
            'Biometric Data',
            sub='encrypted_template · token_hash · feature_dim=512',
            fc=C['bg_store'], ec=C['store'], fs=8)

rounded_box(ax, 12.6, 4.65, 2.8, 0.65,
            'Status Flags',
            sub='is_active=T · has_voted=F · bio_fail_count=0',
            fc=C['bg_store'], ec=C['store'], fs=8)

# S8 – SHA3 hashes
rounded_box(ax, 8.6, 4.65, 3.2, 0.65,
            'Commitment Hashes',
            sub='voter_id_hash = SHA3(voter_id)\ntoken_hash = SHA3(PIN)',
            fc='#EDE7F6', ec=C['crypto'], fs=8.2)

# S9 – Authority registers in registry
rounded_box(ax, 4.6, 5.75, 2.8, 0.65,
            'Register in VoterRegistry',
            sub='Record all fields in-memory roster',
            fc=C['bg_proc'], ec=C['proc'], fs=8.2)

# S10 – Output
rounded_box(ax, 1.1, 3.5, 2.8, 0.65,
            'Registration Confirmed',
            sub='voter_id · kem_pk · sig_pk returned',
            fc=C['bg_output'], ec=C['output'], fs=8.2, bold=True)

rounded_box(ax, 4.6, 3.5, 5.8, 0.65,
            'Audit: SHA3(voter_id) added to nullifier whitelist',
            sub='Ready for Phase 2 (Authentication)',
            fc=C['bg_output'], ec=C['output'], fs=8.2)

# ══════════════════════════════════════════════════════════════════════════════
# ARROWS
# ══════════════════════════════════════════════════════════════════════════════
# Voter → Authority (submit)
arr(ax, 3.9, 9.4, 4.6, 9.4, C['arrow'], lw=1.6)
# Authority → KeyGen trigger
arr(ax, 2.5, 9.1, 2.5, 8.6, C['arrow'])
# Authority → Feature extraction trigger
arr(ax, 6.5, 9.1, 9.2, 8.6, C['crypto'])
# Feature → BioHash
arr(ax, 10.2, 7.95, 10.2, 7.5, C['crypto'])
# BioHash → ML-KEM encrypt
arr(ax, 10.2, 6.85, 10.2, 6.4, C['crypto'])
# KeyGen → registry via authority
arr(ax, 3.9, 8.27, 4.6, 8.27, C['arrow'], label='kem_pk, sig_pk')
# authority → duplicate check
arr(ax, 5.8, 9.1, 5.8, 7.05, C['proc'])
# duplicate check → reject (yes)
arr(ax, 4.4, 6.5, 4.6+2.6/2, 5.2, C['store'], label='Yes')
# duplicate check → register (no)
arr(ax, 7.2, 6.5, 8.6, 6.5, C['proc'], label='No →')
# ML-KEM → store
arr(ax, 11.8, 6.07, 12.6, 6.07, C['crypto'], label='enc template')
# hashes → store
arr(ax, 11.8, 4.97, 12.6, 4.97, C['crypto'])
# hashes → authority
arr(ax, 8.6, 4.97, 7.4, 6.07, C['proc'])
# Authority finalize → registry
arr(ax, 5.5, 5.75, 5.5, 5.2, C['proc'])
# Authority → key store
arr(ax, 6.5, 8.27, 12.6, 7.27, C['store'])
# Authority → flags store
arr(ax, 6.0, 5.75, 12.6, 4.97, C['store'])
# Auth → output
arr(ax, 5.5, 5.75, 2.5, 4.15, C['output'])
arr(ax, 4.6, 3.82, 3.9, 3.82, C['output'])

# ── Legend ────────────────────────────────────────────────────────────────────
items = [
    mpatches.Patch(fc=C['bg_input'],  ec=C['input'],  label='Voter Action'),
    mpatches.Patch(fc=C['bg_proc'],   ec=C['proc'],   label='Authority Processing'),
    mpatches.Patch(fc='#EDE7F6',      ec=C['crypto'], label='Crypto / Bio Layer'),
    mpatches.Patch(fc=C['bg_store'],  ec=C['store'],  label='Secure Storage'),
    mpatches.Patch(fc=C['bg_output'], ec=C['output'], label='Output / Result'),
]
ax.legend(handles=items, loc='lower right', bbox_to_anchor=(0.99, 0.01),
          fontsize=8, framealpha=0.92, ncol=2)

plt.tight_layout(pad=0.3)
plt.savefig('/home/user/RE-code/diagrams/fig2_registration_flow.png',
            dpi=200, bbox_inches='tight', facecolor='#FAFAFA')
plt.close()
print("Fig 2 saved.")
