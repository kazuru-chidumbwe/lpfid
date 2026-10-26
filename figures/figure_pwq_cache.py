#!/usr/bin/env python3
"""Figure 2 of the LPFid manuscript: the wrong pwq_cache binding of CVE-2026-43074 (Section 7.3).

All facts come from lab/s21/CASE-43074-2026-10-08.md: the two local pwq_cache objects of the 6.6.47 pin
(kallsyms position, file, symbol-table index), the binding each kpatch-build release wrote, and the
runtime counts. Usage: python lab/figures/figure_pwq_cache.py -> paper/manuscript/figures/figure-1-pwq-cache.png
"""

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

OUT = Path(__file__).resolve().parents[2] / "paper" / "manuscript" / "figures"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 7.5, "savefig.dpi": 300, "savefig.bbox": "tight"})


def box(ax, x, y, w, h, text, fc, ec="#525252", fs=6.3, mono=False):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.06", fc=fc, ec=ec, lw=0.8))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs,
            family="DejaVu Sans Mono" if mono else "DejaVu Sans")


def arrow(ax, a, b, color, style="-|>", ls="-", lw=1.2, rad=0.0):
    ax.add_patch(FancyArrowPatch(a, b, arrowstyle=style, mutation_scale=9, color=color, lw=lw, linestyle=ls,
                                 connectionstyle=f"arc3,rad={rad}"))


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(7.2, 3.0))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 4.2)
    ax.axis("off")

    # Left: the two modules
    box(ax, 0.1, 2.75, 2.7, 0.9, "kpatch-build v0.9.11 module\n.klp.sym.vmlinux.pwq_cache,1", "#d1e5f0", mono=False)
    box(ax, 0.1, 0.55, 2.7, 0.9, "kpatch-build v0.9.10 module\n.klp.sym.vmlinux.pwq_cache,2", "#fddbc7", mono=False)
    ax.text(1.45, 2.25, "same fix (CVE-2026-43074),\nsame kernel, same gcc 13.3.0", ha="center", va="center",
            fontsize=6.5, color="#525252")

    # Middle: vmlinux with two local copies
    box(ax, 3.6, 0.3, 2.9, 3.6, "", "#f7f7f7")
    ax.text(5.05, 3.65, "6.6.47 vmlinux: two local pwq_cache", ha="center", fontsize=6.8, weight="bold")
    box(ax, 3.8, 2.35, 2.5, 0.95, "position 1 (kallsyms order)\nfs/eventpoll.c\nsymbol-table index 22249", "#ffffff")
    box(ax, 3.8, 0.75, 2.5, 0.95, "position 2 (kallsyms order)\nkernel/workqueue.c\nsymbol-table index 7953", "#ffffff")
    ax.text(5.05, 1.95, "symbol-table order is the reverse:\nworkqueue's copy comes first", ha="center",
            va="center", fontsize=6.3, color="#525252")

    arrow(ax, (2.8, 3.2), (3.8, 2.85), "#2166ac")
    arrow(ax, (2.8, 1.0), (3.8, 1.2), "#b2182b")

    # Right: the outcome
    box(ax, 7.1, 2.55, 2.8, 1.25, "frees eventpoll entries into\neventpoll's cache\n0 wrong-cache frees (3 runs)", "#d1e5f0")
    box(ax, 7.1, 0.35, 2.8, 1.65, "frees eventpoll entries into\nworkqueue's cache\n128 wrong-cache frees per run\nin 64 rounds, slub_debug=F\nno message without debug checks", "#fddbc7")
    arrow(ax, (6.3, 2.85), (7.1, 3.15), "#2166ac")
    arrow(ax, (6.3, 1.2), (7.1, 1.2), "#b2182b")
    ax.text(8.5, 4.0, "after loading: both enabled,\nboth complete their transition", ha="center", va="center",
            fontsize=6.5, color="#525252")
    fig.savefig(OUT / "figure-1-pwq-cache.png")
    print("wrote", OUT / "figure-1-pwq-cache.png")


if __name__ == "__main__":
    main()
