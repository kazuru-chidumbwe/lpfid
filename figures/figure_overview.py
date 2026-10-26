#!/usr/bin/env python3
"""Figure 1 of the LPFid manuscript: from a source fix to a patched kernel, where faults enter, what the kernel
reports, and what LPFid compares (Sections 1 to 5). A schematic; it carries no measured values.
Usage: python lab/figures/figure_overview.py -> paper/manuscript/figures/figure-0-overview.png
"""

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

OUT = Path(__file__).resolve().parents[2] / "paper" / "manuscript" / "figures"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 7.5, "savefig.dpi": 300, "savefig.bbox": "tight"})

GREY, BLUE, RED, GREEN = "#f7f7f7", "#d1e5f0", "#fddbc7", "#d9f0d3"


def box(ax, x, y, w, h, text, fc, ec="#525252", fs=6.6, bold_first=False, lw=0.8):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.08", fc=fc, ec=ec, lw=lw))
    if bold_first:
        head, _, rest = text.partition("\n")
        ax.text(x + w / 2, y + h - 0.2, head, ha="center", va="top", fontsize=fs + 0.4, weight="bold")
        ax.text(x + w / 2, y + (h - 0.35) / 2, rest, ha="center", va="center", fontsize=fs)
    else:
        ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs)


def arrow(ax, a, b, color="#525252", ls="-", lw=1.1, rad=0.0):
    ax.add_patch(FancyArrowPatch(a, b, arrowstyle="-|>", mutation_scale=9, color=color, lw=lw, linestyle=ls,
                                 connectionstyle=f"arc3,rad={rad}"))


def tag(ax, x, y, text, color):
    ax.text(x, y, text, ha="center", va="center", fontsize=6.4, weight="bold", color="white",
            bbox=dict(boxstyle="round,pad=0.25", fc=color, ec="none"))


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(7.4, 3.9))
    ax.set_xlim(0, 15)
    ax.set_ylim(0, 8)
    ax.axis("off")

    # Delivery path (top row)
    y, h = 5.2, 1.7
    box(ax, 0.1, y, 2.2, h, "Source fix\nthe patch to the\nkernel source", GREY, bold_first=True)
    box(ax, 3.0, y, 2.5, h, "Generator\nkpatch-build or\nklp-build", GREY, bold_first=True)
    box(ax, 6.2, y, 2.6, h, "Livepatch module\nnew functions and\nreferences into\nthe kernel", BLUE, bold_first=True)
    box(ax, 9.5, y, 2.2, h, "Shipped\nsigned and\npackaged", GREY, bold_first=True)
    box(ax, 12.4, y, 2.5, h, "Running kernel\nloader and\nlivepatch core\napply it", GREY, bold_first=True)
    for a, b in ((2.3, 3.0), (5.5, 6.2), (8.8, 9.5), (11.7, 12.4)):
        arrow(ax, (a, y + h / 2), (b, y + h / 2))

    # Where faults enter
    ax.text(4.25, 7.55, "faults can enter here", ha="center", fontsize=6.4, color="#b2182b", style="italic")
    ax.text(10.6, 7.55, "and here", ha="center", fontsize=6.4, color="#b2182b", style="italic")
    arrow(ax, (4.25, 7.35), (4.25, 6.95), color="#b2182b")
    arrow(ax, (10.6, 7.35), (10.6, 6.95), color="#b2182b")
    tag(ax, 4.25, 4.75, "RQ2", "#b2182b")
    tag(ax, 10.6, 4.75, "RQ3", "#b2182b")

    # The kernel's signals
    box(ax, 12.4, 2.0, 2.5, 2.45, "Kernel signals\nmodule loads\nenabled = 1\ntransition = 0\n\naccepted,\nnot verified",
        RED, bold_first=True, fs=6.3)
    arrow(ax, (13.65, y), (13.65, 4.45))
    tag(ax, 13.65, 1.65, "RQ1", "#b2182b")

    # LPFid lane (bottom row)
    box(ax, 0.1, 1.2, 2.2, 1.7, "Reference\nindependent\ncompile of the\npatched source", GREEN, bold_first=True, fs=6.3)
    arrow(ax, (1.2, y), (1.2, 2.9))
    box(ax, 6.2, 0.25, 2.6, 1.55, "Kernel image\nvmlinux of the\ntarget build", GREY, bold_first=True, fs=6.3)
    box(ax, 3.0, 2.35, 5.8, 1.9,
        "LPFid static checks\nbinding check: where each reference points\nposition check: which copy of a shared name\nimmediate check: constants in instructions",
        GREEN, bold_first=True, fs=6.3, lw=1.1)
    arrow(ax, (2.3, 2.05), (3.0, 2.9))
    arrow(ax, (7.5, y), (7.5, 4.25), color="#2166ac")
    arrow(ax, (7.5, 1.8), (7.5, 2.35))
    ax.text(10.55, 3.3, "CONSISTENT or\nDIVERGENT, per\npatched function", ha="center", va="center", fontsize=6.4)
    arrow(ax, (8.8, 3.3), (9.45, 3.3))
    tag(ax, 5.9, 1.9, "RQ4", "#2166ac")

    fig.savefig(OUT / "figure-0-overview.png")
    print(OUT / "figure-0-overview.png")


if __name__ == "__main__":
    main()
