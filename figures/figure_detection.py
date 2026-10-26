#!/usr/bin/env python3
"""Figure 3 of the LPFid manuscript: detection rate per operator for each check, with Wilson 95%
intervals (a), and what the module loader and livepatch core did with the redirect mutants (b).

Reads only committed result files; rerun whenever a check's results are added (the CHECKS list below
says which file each series comes from; series whose file is missing are left out, not drawn as zero).
Usage: python lab/figures/figure_detection.py   ->  paper/manuscript/figures/figure-2-detection.png
"""

from __future__ import annotations

import json
import math
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

LAB = Path(__file__).resolve().parents[1]
OUT = LAB.parent / "paper" / "manuscript" / "figures"
OPS = ["redirect", "swap", "sympos", "addend", "dropcall", "constant"]
CLASS = {"redirect": "binding", "swap": "binding", "sympos": "binding", "addend": "addend",
         "dropcall": "scope", "constant": "body"}
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8, "axes.spines.top": False,
                     "axes.spines.right": False, "savefig.dpi": 300, "savefig.bbox": "tight"})


def wilson(k: int, n: int, z: float = 1.959964) -> tuple[float, float, float]:
    if n == 0:
        return float("nan"), float("nan"), float("nan")
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return p, max(0.0, c - h), min(1.0, c + h)


def s2_series(version: str, corpus: str) -> dict[str, tuple[int, int]]:
    s = json.loads((LAB / "s2/s2-s12-fixtures-2026-10-09.json").read_text(encoding="utf-8"))["summary"]
    po = s[corpus]["per_operator"]
    return {op: (po[op][version]["detected"], po[op]["scored_dedup"]) for op in OPS if op in po and version in po[op]}


def loader_fixture_redirect() -> dict[str, tuple[int, int]]:
    a = json.loads((LAB / "baseline/loader-fixtures-analysis-2026-10-09.json").read_text(encoding="utf-8"))
    lp = a["livepatch_modules_only"]
    return {"redirect": (lp["mutants"] - lp["loader_accepted"], lp["mutants"])}


def s2_v12(corpus: str) -> dict[str, tuple[int, int]]:
    """v1.2 = v1.1 plus the mutants only v1.2 detects (lab/s12/oracle-v12-validation-2026-10-09.json)."""
    base = s2_series("v1.1", corpus)
    extra = json.loads((LAB / "s12/oracle-v12-validation-2026-10-09.json").read_text(encoding="utf-8"))["summary"]["detected_by_v12_only"]
    tag = "s2_s12_" if corpus == "s12" else "s2_fixtures_"
    for e in extra:
        key = e.split()[0]
        if key.startswith(tag):
            op = key[len(tag):]
            k, n = base[op]
            base[op] = (k + 1, n)
    return base


def ps3_mutants() -> dict[str, tuple[int, int]]:
    """Presence test on the operator mutants of the 12 judged fixes, files whose parent PS3 judged patched."""
    d = json.loads((LAB / "results-2026-10-10/s20-ps3-s2mut-r2.json").read_text(encoding="utf-8"))
    out: dict[str, list[int]] = {}
    for r in d["rows"]:
        if not r.get("supported"):
            continue
        for v in r["files"].values():
            if v.get("module") != "patch":
                continue
            for mid, verdict in (v.get("extra") or {}).items():
                op = mid.rsplit("-", 1)[0]
                k, n = out.get(op, [0, 0])
                out[op] = [k + (verdict == "vuln"), n + 1]
    return {op: (k, n) for op, (k, n) in out.items()}


def loader_s2(corpus: str) -> dict[str, tuple[int, int]]:
    a = json.loads((LAB / "baseline/loader-s2-analysis-2026-10-09.json").read_text(encoding="utf-8"))["sets"][corpus]
    return {op: (v["loader_detected"], v["livepatch"]) for op, v in a.items() if op in OPS and v["livepatch"]}


# (label, function, colour, marker). Add a series here when its results are committed.
CHECKS = [
    ("module loader and livepatch core, real-fix modules", lambda: loader_s2("s12"), "#b2182b", "s"),
    ("module loader and livepatch core, fixture modules", lambda: loader_s2("fixtures"), "#f4a582", "v"),
    ("patch presence test (PS3), real-fix modules", ps3_mutants, "#762a83", "^"),
    ("binding oracle v1.2, real-fix modules", lambda: s2_v12("s12"), "#2166ac", "o"),
    ("binding oracle v1.2, fixture modules", lambda: s2_v12("fixtures"), "#67a9cf", "D"),
]


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    fig = plt.figure(figsize=(7.2, 3.1))
    ax = fig.add_axes([0.07, 0.3, 0.6, 0.62])
    width = 0.6
    for j, (label, fn, col, mk) in enumerate(CHECKS):
        try:
            data = fn()
        except FileNotFoundError:
            continue
        off = (j - (len(CHECKS) - 1) / 2) * width / len(CHECKS)
        for i, op in enumerate(OPS):
            if op not in data:
                continue
            k, n = data[op]
            p, lo, hi = wilson(k, n)
            ax.errorbar(i + off, 100 * p, yerr=[[max(0.0, 100 * (p - lo))], [max(0.0, 100 * (hi - p))]], fmt=mk, color=col,
                        markersize=4, capsize=2, linewidth=0.8, label=label if i == OPS.index(next(iter(data))) else None)
    ax.set_xticks(range(len(OPS)), [f"{op}\n({CLASS[op]})" for op in OPS])
    ax.set_ylabel("mutants detected (%)")
    ax.set_ylim(-4, 104)
    ax.set_xlim(-0.6, len(OPS) - 0.4)
    ax.axhline(0, color="#d9d9d9", linewidth=0.5, zorder=0)
    ax.legend(fontsize=6.5, frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.2), ncol=2)
    ax.set_title("(a) detection per operator, Wilson 95% intervals", loc="left", fontsize=8)

    s12 = json.loads((LAB / "baseline/loader-s2-analysis-2026-10-09.json").read_text(encoding="utf-8"))["sets"]["s12"]
    lo: dict[str, int] = {}
    for op, v in s12.items():
        for k, n in v.get("outcomes", {}).items():
            lo[k] = lo.get(k, 0) + n
    parts = [("loaded, enabled,\ntransition done", lo.get("LOADED_ENABLED", 0), "#f4a582"),
             ("kernel crash", lo.get("CRASH", 0), "#2166ac"),
             ("not enabled", lo.get("NOT_ENABLED", 0), "#4393c3"),
             ("rejected at load", lo.get("LOAD_FAIL", 0), "#92c5de"),
             ("transition not done", lo.get("TIMEOUT", 0), "#d1e5f0")]
    ax2 = fig.add_axes([0.76, 0.3, 0.07, 0.62])
    bottom, centres = 0, []
    for name, v, c in parts:
        ax2.bar(0, v, bottom=bottom, color=c, edgecolor="white", linewidth=0.5, width=0.8)
        centres.append(bottom + v / 2)
        bottom += v
    gap = 0.075 * bottom          # labels at least this far apart, pushed downwards from the top
    ys = list(centres)
    for i in range(len(ys) - 2, -1, -1):
        ys[i] = min(ys[i], ys[i + 1] - gap)
    for (name, v, _), yc, y in zip(parts, centres, ys):
        ax2.annotate(f"{name} ({v})", xy=(0.4, yc), xytext=(0.6, y), va="center", fontsize=6.5,
                     arrowprops={"arrowstyle": "-", "linewidth": 0.4, "color": "#969696"})
    ax2.set_xlim(-0.5, 0.5)
    ax2.set_ylim(0, bottom)
    ax2.set_xticks([])
    ax2.set_ylabel(f"operator mutants of real fixes ({bottom})")
    ax2.set_title("(b) loader", loc="left", fontsize=8)
    fig.savefig(OUT / "figure-2-detection.png")
    print("wrote", OUT / "figure-2-detection.png")


if __name__ == "__main__":
    main()
