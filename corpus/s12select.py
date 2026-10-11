#!/usr/bin/env python3
"""S12 real-fix selection (pre-registered rule: internal/S12-PREREG-2026-10-07.md).

Deterministic given (vulns.git commit, stable fetch, pin trees). Writes, per branch:
  candidates.tsv  every CVE that reached step 2, with the step it failed and why
  funnel.json     counts after each step
  selection.json  the seeded main sample (<=40) and over-cap sample (<=10)

Usage: s12select.py VULNS_DIR STABLE_REPO OUT_DIR BRANCH=PIN_VERSION=PIN_TREE ...
"""
from __future__ import annotations

import glob
import json
import os
import random
import re
import subprocess
import sys
from pathlib import Path

MAIN_N, OVERCAP_N = 40, 10
MAX_FILES, MAX_FUNCS = 2, 3


def ver(s: str) -> tuple:
    parts = [int(x) for x in re.findall(r"\d+", s)[:3]]
    return tuple(parts + [0] * (3 - len(parts)))


def git(repo: str, *args: str) -> str:
    return subprocess.run(["git", "-C", repo, *args], check=True, capture_output=True, text=True,
                          errors="replace").stdout


def fix_for_branch(dyad: Path, branch: str, pin: str):
    """Return the stable fix sha for BRANCH if the CVE is present in PIN and fixed after it."""
    b, p = ver(branch)[:2], ver(pin)
    for line in dyad.read_text(errors="replace").splitlines():
        if line.startswith("#") or line.count(":") != 3:
            continue
        vv, _vs, fv, fs = line.split(":")
        if fv == "0" or fs == "0" or ver(fv)[:2] != b or len(re.findall(r"\d+", fv)) < 3:
            continue
        if ver(fv) <= p:
            continue  # fixed at or before the pin: pin is not vulnerable
        if vv != "0":
            v = ver(vv)
            if v[:2] > b or (v[:2] == b and len(re.findall(r"\d+", vv)) >= 3 and v > p):
                continue  # bug introduced after the pin
        return fs, fv
    return None


def functions(src: str):
    """Kernel style: a function body opens with '{' alone at column 0 and closes with '}' at column 0.
    The header is the run of non-blank lines above the '{'; the name is the identifier before its first '('."""
    lines, out = src.splitlines(), []
    i = 0
    while i < len(lines):
        if lines[i] == "{":
            h = i - 1
            while h > 0 and lines[h - 1].strip() and not lines[h - 1].rstrip().endswith((";", "}", "*/"))                     and not lines[h - 1].startswith("#"):
                h -= 1
            header = " ".join(lines[h:i])
            m = re.search(r"([A-Za-z_]\w*)\s*\(", header)
            k = i + 1
            while k < len(lines) and lines[k] != "}":
                k += 1
            if m:
                out.append((m.group(1), h + 1, k + 1, "inline" in header))
            i = k + 1
            continue
        i += 1
    return out


def changed_old_lines(diff_for_file: str):
    """Old-side line numbers touched by the hunk (removed lines, and the insertion point of added lines)."""
    touched, old = [], 0
    for line in diff_for_file.splitlines():
        h = re.match(r"^@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@", line)
        if h:
            old = int(h.group(1))
            continue
        if line.startswith("---") or line.startswith("+++"):
            continue
        if line.startswith("-"):
            touched.append(old)
            old += 1
        elif line.startswith("+"):
            touched.append(old)
        elif line.startswith(" "):
            old += 1
    return touched


def split_diff(diff: str):
    files, cur, buf = {}, None, []
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            if cur:
                files[cur] = "\n".join(buf)
            cur, buf = line.split(" b/", 1)[1], []
        buf.append(line)
    if cur:
        files[cur] = "\n".join(buf)
    return files


def classify(stable: str, sha: str, tree: str):
    """Return (failed_step or None, reason, info)."""
    status = git(stable, "show", "--format=", "--name-status", sha).split("\n")
    entries = [l.split("\t") for l in status if l.strip()]
    paths = [e[-1] for e in entries]
    info = {"files": paths}
    if not paths or any(e[0] != "M" or not e[-1].endswith(".c") for e in entries):
        return 3, "not only modified .c files", info
    unbuilt = [p for p in paths if not os.path.exists(os.path.join(tree, p[:-2] + ".o"))]
    if unbuilt:
        return 4, "not compiled in pin config: " + ",".join(unbuilt), info
    diff = git(stable, "show", "--format=", "--no-color", "-U3", sha)
    funcs, toplevel, inline = set(), False, False
    for path, d in split_diff(diff).items():
        try:
            parent = git(stable, "show", f"{sha}^:{path}")
        except subprocess.CalledProcessError:
            parent = Path(tree, path).read_text(errors="replace")
            info["parent_from_pin"] = True
        defs = functions(parent)
        for ln in changed_old_lines(d):
            hit = [f for f in defs if f[1] <= ln <= f[2]]
            if hit:
                funcs.add((path, hit[0][0]))
                inline |= hit[0][3]
            else:
                toplevel = True
    info.update(functions=sorted(f"{p}:{n}" for p, n in funcs), toplevel_change=toplevel, inline=inline)
    info["type"] = "T3" if toplevel else ("T2" if len(funcs) >= 2 or inline else "T1")
    overcap = len(paths) > MAX_FILES or len(funcs) > MAX_FUNCS
    if any(p.startswith("arch/") and not p.startswith("arch/x86/") for p in paths):
        return 5, "non-x86 arch", info
    r = subprocess.run(["patch", "-p1", "--dry-run", "--fuzz=2", "-d", tree], input=diff,
                       capture_output=True, text=True)
    info["apply_log"] = r.stdout.strip()[-400:]
    if r.returncode != 0:
        return 6, "does not apply to pin", info
    info["fuzz"] = "fuzz" in r.stdout
    if overcap:
        return 7, f"over cap ({len(paths)} files, {len(funcs)} functions)", info
    return None, "eligible", info


def main() -> int:
    vulns, stable, out = sys.argv[1], sys.argv[2], Path(sys.argv[3])
    out.mkdir(parents=True, exist_ok=True)
    vcommit = git(vulns, "rev-parse", "HEAD").strip()
    seed = int(vcommit[:8], 16)
    dyads = sorted(glob.glob(os.path.join(vulns, "cve", "published", "*", "*.dyad")))
    total = len({Path(d).stem for d in dyads})
    meta = {"vulns_commit": vcommit, "seed_hex": vcommit[:8], "published_cves_with_dyad": total}
    for spec in sys.argv[4:]:
        branch, pin, tree = spec.split("=", 2)
        bdir = out / branch
        bdir.mkdir(exist_ok=True)
        funnel = {"1_published": total, "2_fixed_after_pin": 0}
        steps = {3: "3_only_modified_c", 4: "4_compiled_in_pin", 5: "5_x86_relevant",
                 6: "6_applies_to_pin", 7: "7_within_cap"}
        fails = {k: 0 for k in steps}
        eligible, overcap, rows = [], [], []
        for d in dyads:
            hit = fix_for_branch(Path(d), branch, pin)
            if not hit:
                continue
            funnel["2_fixed_after_pin"] += 1
            cve, (sha, fixver) = Path(d).stem, hit
            try:
                failed, why, info = classify(stable, sha, tree)
            except subprocess.CalledProcessError as e:
                failed, why, info = 3, "stable commit not available: " + (e.stderr or "")[:120], {}
            if failed:
                fails[failed] += 1
            rows.append({"cve": cve, "stable_sha": sha, "fixed_in": fixver, "failed_step": failed,
                         "reason": why, **info})
            if failed is None:
                eligible.append(cve)
            elif failed == 7:
                overcap.append(cve)
        n = funnel["2_fixed_after_pin"]
        for k in sorted(steps):
            n -= fails[k]
            funnel[steps[k]] = n
        funnel["overcap_pool"] = len(overcap)
        main_s = sorted(random.Random(seed).sample(sorted(eligible), min(MAIN_N, len(eligible))))
        over_s = sorted(random.Random(seed + 1).sample(sorted(overcap), min(OVERCAP_N, len(overcap))))
        funnel["8_main_sample"], funnel["8_overcap_sample"] = len(main_s), len(over_s)
        with open(bdir / "candidates.tsv", "w") as f:
            f.write("cve\tstable_sha\tfixed_in\tfailed_step\treason\ttype\tfiles\tfunctions\n")
            for r in rows:
                f.write("\t".join([r["cve"], r["stable_sha"], r["fixed_in"], str(r["failed_step"] or ""),
                                   r["reason"], r.get("type", ""), ",".join(r.get("files", [])),
                                   ",".join(r.get("functions", []))]) + "\n")
        byid = {r["cve"]: r for r in rows}
        json.dump({**meta, "branch": branch, "pin": pin, "funnel": funnel}, open(bdir / "funnel.json", "w"), indent=1)
        json.dump({**meta, "branch": branch, "pin": pin,
                   "main": [byid[c] for c in main_s], "overcap": [byid[c] for c in over_s]},
                  open(bdir / "selection.json", "w"), indent=1)
        print(branch, json.dumps(funnel))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
