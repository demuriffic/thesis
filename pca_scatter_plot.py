"""
PCA Biplot (no arrows) — Scatter + Loadings Bar Charts
--------------------------------------------------------
Left  : clean PCA scatter plot colored by label
Right : PC1 and PC2 loadings bar charts stacked vertically
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.ticker as ticker
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA

# ── 1. Load & fit ─────────────────────────────────────────────────────────────
df = pd.read_csv("full_thesis_features.csv")

FEATURE_COLS = [
    "math_density", "loop_density", "graph_density",
    "instr_variance", "opcode_entropy", "call_density", "mem_density",
]
FEATURE_LABELS = [
    "Math Density", "Loop Density", "Graph Density",
    "Instr. Variance", "Opcode Entropy", "Call Density", "Mem Density",
]

X = df[FEATURE_COLS].values
y = df["label"].values

X_scaled = StandardScaler().fit_transform(X)
pca      = PCA(n_components=2, random_state=42)
X_pca    = pca.fit_transform(X_scaled)

var1, var2 = pca.explained_variance_ratio_ * 100
pc1_vals   = pca.components_[0]
pc2_vals   = pca.components_[1]

# Sort by absolute loading (strongest at top)
order1 = np.argsort(np.abs(pc1_vals))
order2 = np.argsort(np.abs(pc2_vals))

# ── 2. Colours ────────────────────────────────────────────────────────────────
COLOR0    = "#378ADD"   # blue   — benign
COLOR1    = "#D4537E"   # coral  — cryptojacking
POS_COLOR = "#534AB7"   # purple — positive loading
NEG_COLOR = "#D4537E"   # coral  — negative loading

plt.rcParams.update({
    "font.family"   : "DejaVu Sans",
    "font.size"     : 10,
    "axes.linewidth": 0.7,
})

# ── 3. Layout ─────────────────────────────────────────────────────────────────
fig = plt.figure(figsize=(13, 5.8), facecolor="white")
gs  = fig.add_gridspec(
    2, 2,
    width_ratios=[1.5, 1],
    hspace=0.52,
    wspace=0.38,
    left=0.07, right=0.97,
    top=0.88,  bottom=0.11,
)

ax_scatter = fig.add_subplot(gs[:, 0])   # full left column
ax_pc1     = fig.add_subplot(gs[0, 1])   # top-right
ax_pc2     = fig.add_subplot(gs[1, 1])   # bottom-right

# ── 4. Scatter plot ───────────────────────────────────────────────────────────
mask0, mask1 = y == 0, y == 1

scatter_kw = dict(s=20, linewidths=0, alpha=0.50, rasterized=True)

ax_scatter.scatter(
    X_pca[mask0, 0], X_pca[mask0, 1],
    c=COLOR0, label=f"Benign  (n={mask0.sum():,})",
    **scatter_kw,
)
ax_scatter.scatter(
    X_pca[mask1, 0], X_pca[mask1, 1],
    c=COLOR1, label=f"Cryptojacking  (n={mask1.sum():,})",
    marker="^", **scatter_kw,
)

# Subtle reference lines
ax_scatter.axhline(0, color="#cccccc", lw=0.6, zorder=0)
ax_scatter.axvline(0, color="#cccccc", lw=0.6, zorder=0)

# Grid & spines
ax_scatter.grid(True, linestyle="--", linewidth=0.4,
                color="#cccccc", alpha=0.75)
ax_scatter.set_axisbelow(True)
for spine in ax_scatter.spines.values():
    spine.set_color("#888888")
ax_scatter.tick_params(colors="#444444", length=3.5)
ax_scatter.xaxis.set_major_locator(ticker.MaxNLocator(6))
ax_scatter.yaxis.set_major_locator(ticker.MaxNLocator(6))

# Labels & title
ax_scatter.set_xlabel(f"Principal Component 1  ({var1:.1f}% variance)", labelpad=7)
ax_scatter.set_ylabel(f"Principal Component 2  ({var2:.1f}% variance)", labelpad=7)
ax_scatter.set_title(
    "PCA Visualization of Extracted Binary Features",
    fontsize=12, fontweight="semibold", pad=10,
)

# Legend
legend = ax_scatter.legend(
    frameon=True, framealpha=0.92, edgecolor="#cccccc",
    fontsize=9, markerscale=1.4,
    handletextpad=0.4, borderpad=0.55,
)
legend.get_frame().set_linewidth(0.6)

# ── 5. Loadings bar chart helper ──────────────────────────────────────────────
def draw_loadings(ax, vals, order, title, var_pct):
    sorted_labels = [FEATURE_LABELS[i] for i in order]
    sorted_vals   = vals[order]
    colors        = [POS_COLOR if v >= 0 else NEG_COLOR for v in sorted_vals]

    bars = ax.barh(
        sorted_labels, sorted_vals,
        color=colors, height=0.52,
        edgecolor="none", zorder=3,
    )

    ax.axvline(0, color="#888888", lw=0.8, zorder=2)
    ax.set_xlim(-0.72, 0.72)

    # Value labels on bars
    for bar, val in zip(bars, sorted_vals):
        pad = 0.025 if val >= 0 else -0.025
        ha  = "left"  if val >= 0 else "right"
        ax.text(
            val + pad,
            bar.get_y() + bar.get_height() / 2,
            f"{val:+.3f}",
            va="center", ha=ha,
            fontsize=7.5, color="#333333",
        )

    # Variance explained annotation
    ax.text(
        0.98, 0.03, f"{var_pct:.1f}% variance explained",
        transform=ax.transAxes,
        ha="right", va="bottom",
        fontsize=7.5, color="#666666", style="italic",
    )

    ax.set_title(title, fontsize=10, fontweight="semibold", pad=7)
    ax.set_xlabel("Loading weight", fontsize=8.5, labelpad=4)

    ax.grid(axis="x", linestyle="--", linewidth=0.4,
            color="#cccccc", alpha=0.9, zorder=1)
    ax.set_axisbelow(True)

    for spine in ["top", "right"]:
        ax.spines[spine].set_visible(False)
    ax.spines["left"].set_color("#cccccc")
    ax.spines["bottom"].set_color("#cccccc")
    ax.tick_params(axis="y", length=0, labelsize=8.5)
    ax.tick_params(axis="x", length=3,  labelsize=7.5, colors="#444444")

# ── 6. Draw loadings charts ───────────────────────────────────────────────────
draw_loadings(ax_pc1, pc1_vals, order1, "PC1 — Feature Loadings", var1)
draw_loadings(ax_pc2, pc2_vals, order2, "PC2 — Feature Loadings", var2)

# ── 7. Shared legend for loading colours ─────────────────────────────────────
pos_patch = mpatches.Patch(color=POS_COLOR, label="Positive loading")
neg_patch = mpatches.Patch(color=NEG_COLOR, label="Negative loading")
fig.legend(
    handles=[pos_patch, neg_patch],
    loc="upper right",
    ncol=1,
    fontsize=8.5,
    frameon=True,
    framealpha=0.9,
    edgecolor="#cccccc",
    bbox_to_anchor=(0.97, 0.97),
)

# ── 8. Save ───────────────────────────────────────────────────────────────────
out = "pca_biplot_clean.png"
fig.savefig(out, dpi=300, bbox_inches="tight",
            facecolor="white", edgecolor="none")
print(f"Saved → {out}")
plt.close(fig)