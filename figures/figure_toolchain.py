#!/usr/bin/env python3
"""Figure 4 of the LPFid manuscript: false-alarm rate of the two build-differential checks as the
reference toolchain moves away from the module's. Shows why the strict toolchain gate (T1) is the default.

Points (counts so the Wilson intervals are reproducible; sources in comments):
  binding oracle v1.3, gate off:
    same build (gcc 13 module vs gcc 13 reference):            0 / 123   lab/s30/s30.json distance0
    same version, different build (Ubuntu vs Debian gcc 13.3): 7 / 81    7.4 benign rebuilds, s21 rdev t1=version
    one gcc major version (gcc 14 module vs gcc 13 reference): 18 / 33   lab/s30/s30.json distance1
  immediate-differential check (S27):
    same build:                                                 0 / 122  lab/s27 SUMMARY (fa_same)
    one gcc major version:                                      12 / 33  lab/s27 SUMMARY (fa_cross)

Usage: python lab/figures/figure_toolchain.py  ->  paper/manuscript/figures/figure-3-toolchain.png
"""
from __future__ import annotations

import math
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

OUT = Path(__file__).resolve().parents[1].parent / "paper" / "manuscript" / "figures"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8, "axes.spines.top": False,
                     "axes.spines.right": False, "savefig.dpi": 300, "savefig.bbox": "tight"})


def wilson(k: int, n: int, z: float = 1.959964) -> tuple[float, float, float]:
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return 100 * p, 100 * max(0.0, c - h), 100 * min(1.0, c + h)


# (x position, k, n) per distance rung
BINDING = [(0, 0, 123), (1, 7, 81), (2, 18, 33)]
IMMEDIATE = [(0, 0, 122), (2, 12, 33)]
LABELS = ["same\nbuild", "same version,\ndifferent build", "one gcc\nmajor version"]


def series(points, dx):
    xs, ys, lo, hi = [], [], [], []
    for x, k, n in points:
        p, l, h = wilson(k, n)
        xs.append(x + dx); ys.append(p); lo.append(p - l); hi.append(h - p)
    return xs, ys, [lo, hi]


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(5.4, 3.3))
    for pts, label, style, colour, marker, dx in (
        (BINDING, "binding oracle", "-", "#1f3b73", "o", -0.04),
        (IMMEDIATE, "immediate-differential check", "--", "#b5651d", "s", 0.04),
    ):
        xs, ys, err = series(pts, dx)
        ax.errorbar(xs, ys, yerr=err, fmt=marker + style, color=colour, capsize=3,
                    markersize=5, linewidth=1.4, label=label)
    ax.set_xticks([0, 1, 2]); ax.set_xticklabels(LABELS)
    ax.set_xlim(-0.3, 2.35); ax.set_ylim(-2, 80)
    ax.set_ylabel("false-alarm rate on faithful modules (%)")
    ax.set_xlabel("distance from the module's toolchain to the reference's")
    ax.legend(loc="upper left", frameon=False)
    ax.grid(axis="y", linewidth=0.3, alpha=0.4)
    fig.savefig(OUT / "figure-3-toolchain.png")
    print("wrote", OUT / "figure-3-toolchain.png")


if __name__ == "__main__":
    main()
