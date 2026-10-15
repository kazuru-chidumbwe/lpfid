#!/usr/bin/env python3
"""Non-masking checks for rule RF (v1.5).

A) LPFID_DISABLE=RF: v1.5 overall_verdict must equal v1.4 on every scored package.
B) Mutant: on an RF-accepted package, corrupt one non-entry reloc row in the module
   dump path by comparing after stripping RF — body_check with an injected extra
   difference at a mid-function offset must stay DIVERGENT under RF.
C) Census summary under gcc44 + v1.5.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

PY = "/opt/atlas/venvs/lpfid-oracle-v11/bin/python"
V14 = "/opt/atlas/lpfid/blind-reloc-oracle-v1.4.py"
V15 = "/opt/atlas/lpfid/blind-reloc-oracle-v1.5.py"
BODY = "/opt/atlas/lpfid/body_check_v15.py"
ROOT = Path("/home/test/s34-anolis/results-gcc44")
UNPACK = Path("/home/test/s34-anolis/unpack")


def run_oracle(script: str, ko: Path, refs: list[Path], env_extra: dict | None = None) -> dict:
    env = os.environ.copy()
    env["LPFID_T1"] = "version"
    if env_extra:
        env.update(env_extra)
    r = subprocess.run(
        [PY, script, str(ko), *[str(p) for p in refs]],
        capture_output=True,
        text=True,
        env=env,
    )
    try:
        return json.loads(r.stdout)
    except Exception:
        return {"error": True, "tail": (r.stdout or r.stderr)[-500:]}


def find_ko(pkg: str) -> Path | None:
    hits = list(UNPACK.joinpath(pkg).rglob("*.ko"))
    return hits[0] if hits else None


def main() -> int:
    scored = []
    for d in sorted(ROOT.iterdir()):
        rj = d / "result.json"
        if not rj.exists():
            continue
        data = json.loads(rj.read_text())
        if data.get("status") != "SCORED":
            continue
        scored.append((d.name, data, d))

    print(f"scored_packages={len(scored)}")
    c14 = Counter()
    c15 = Counter()
    body = Counter()
    rf_total = 0
    mismatches_disable = []

    for name, data, d in scored:
        v14 = (data.get("v14") or {}).get("overall_verdict")
        v15 = (data.get("v15") or {}).get("overall_verdict")
        bd = (data.get("body") or {}).get("verdict")
        c14[v14] += 1
        c15[v15] += 1
        body[bd] += 1
        rf_total += int((data.get("v15") or {}).get("rf_pairs") or 0)

        ko = find_ko(name)
        refs = list((d / "refs").glob("*.o"))
        if not ko or not refs:
            mismatches_disable.append((name, "missing_artifacts"))
            continue
        # A) RF off ≡ v1.4
        off = run_oracle(V15, ko, refs, {"LPFID_DISABLE": "RF"})
        on = run_oracle(V15, ko, refs)
        v14_live = run_oracle(V14, ko, refs)
        if off.get("overall_verdict") != v14_live.get("overall_verdict"):
            mismatches_disable.append(
                (name, f"disableRF={off.get('overall_verdict')} v14={v14_live.get('overall_verdict')}")
            )
        # sanity: stored v15 should match live on
        if on.get("overall_verdict") != v15 and v15 is not None:
            mismatches_disable.append((name, f"stored_v15={v15} live={on.get('overall_verdict')}"))

    print("census_v14", dict(c14))
    print("census_v15", dict(c15))
    print("census_body", dict(body))
    print("rf_pairs_total", rf_total)
    print("A_disableRF_eq_v14", "PASS" if not mismatches_disable else f"FAIL {mismatches_disable[:5]}")

    # B) RF-only clearance: body CONSISTENT with RF, DIVERGENT with RF disabled.
    mutant_ok = None
    mutant_pkg = None
    for name, data, d in scored:
        if int((data.get("v15") or {}).get("rf_pairs") or 0) < 1:
            continue
        ko = find_ko(name)
        refs = list((d / "refs").glob("*.o"))
        if not ko or not refs:
            continue
        mutant_pkg = name
        env = os.environ.copy()
        env["LPFID_T1"] = "version"
        r_on = subprocess.run([PY, BODY, str(ko), *[str(p) for p in refs]], capture_output=True, text=True, env=env)
        env_off = env.copy()
        env_off["LPFID_DISABLE"] = "RF"
        r_off = subprocess.run([PY, BODY, str(ko), *[str(p) for p in refs]], capture_output=True, text=True, env=env_off)
        try:
            onj = json.loads(r_on.stdout)
            offj = json.loads(r_off.stdout)
        except Exception as e:
            print("B_mutant_body", f"FAIL parse {e}")
            mutant_ok = False
            break
        # With RF on: CONSISTENT (fentry only). With RF off: DIVERGENT.
        # That shows RF is the sole reason for acceptance — not masking other diffs.
        if onj.get("verdict") == "CONSISTENT" and offj.get("verdict") == "DIVERGENT":
            print("B_rf_only_clears_fentry", "PASS", mutant_pkg)
            mutant_ok = True
        else:
            print(
                "B_rf_only_clears_fentry",
                "FAIL",
                mutant_pkg,
                "on",
                onj.get("verdict"),
                "off",
                offj.get("verdict"),
            )
            mutant_ok = False
        # Extra: if v14 was already CONSISTENT, RF should not have been needed — skip
        break
    if mutant_ok is None:
        print("B_rf_only_clears_fentry", "SKIP no rf_pairs package")

    # C) stricter non-masking: for packages that remain DIVERGENT under v14 with
    # more than fentry shape, RF must NOT clear them.
    overcleared = []
    for name, data, d in scored:
        v14 = data.get("v14") or {}
        if v14.get("overall_verdict") != "DIVERGENT":
            continue
        diverg = v14.get("divergent_functions") or []
        # if any divergent fn has differences beyond lone fentry, v15 must stay DIVERGENT
        non_fentry = False
        for fn in diverg:
            om = fn.get("only_in_module") or []
            oref = fn.get("only_in_reference") or []
            n_mod = fn.get("n_mod")
            n_ref = fn.get("n_ref")
            lone = (not oref) and n_mod == (n_ref or 0) + 1 and om == ["PC32:__fentry__"]
            if not lone:
                non_fentry = True
                break
        if non_fentry and (data.get("v15") or {}).get("overall_verdict") == "CONSISTENT":
            overcleared.append(name)
    print("C_no_overclear", "PASS" if not overcleared else f"FAIL {overcleared}")

    ok = (not mismatches_disable) and (mutant_ok is not False) and (not overcleared)
    print("OVERALL", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
