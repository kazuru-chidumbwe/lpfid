#!/usr/bin/env python3
"""S6b runner (S6B-PREREG-2026-10-11.md).
build-b1  build every B1 source as an external module with debug information against its pin (gcc 13), and a
          copy stripped with `strip --strip-debug` for B1s
scan      run v1 (pre-revert-scan.py) and v2 (pre-revert-scan-v2.py, --types = pin kernel/livepatch/core.o) on every
          labelled module that exists; B3 and held-out H modules are picked up when their builds exist
score     confusion per population for v1 and v2 (positive = OUT_OF_SCOPE; UNDETERMINED counts as OUT_OF_SCOPE)
Usage (build host): python3 s6b_run.py build-b1 | scan | score
Output: /opt/atlas/lpfid/s6b/{build,scan,score.json}
"""
import hashlib
import importlib.util
import json
import math
import os
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

A = Path("/opt/atlas")
C = A / "livepatch-corpus"
S = A / "lpfid/s6b"
LABELS = json.loads((S / "heldout-labels.json").read_text())
PY = A / "venvs/lpfid-oracle-v11/bin/python"
V1, V2 = A / "lpfid/pre-revert-scan.py", A / "lpfid/pre-revert-scan-v2.py"
V2_SHA = "ef82b9e7cbb64a7e14b07e156a79bd4542a24ddb305ddda9920800e0ba1ea9cf"
TREES = {"6.12.51": C / "linux-6.12.51", "6.19": C / "linux-6.19", "6.12": C / "linux-6.12.51", "6.6": C / "pilot-work/linux",
         "6.1": C / "linux-second-pin", "5.15": C / "linux-5.15.173"}


def gcc_path() -> str:
    spec = importlib.util.spec_from_file_location("b", A / "s12/s12build.py")
    b = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(b)
    return str(b.gccbin("gcc-13"))


def build_b1() -> int:
    env = dict(os.environ, PATH=f"{gcc_path()}:{os.environ['PATH']}")
    rows = [r for r in LABELS["rows"] if r["population"] == "B1"]
    for pin in sorted({r["pin"] for r in rows}):
        for d in sorted({str(Path(r["source"]).parent) for r in rows if r["pin"] == pin}):
            bd = S / "build" / pin / d.replace("/", "__")
            shutil.rmtree(bd, ignore_errors=True)
            bd.mkdir(parents=True)
            src = TREES[pin] / d
            for f in src.glob("*.c"):
                shutil.copy2(f, bd / f.name)
            for f in src.glob("*.h"):
                shutil.copy2(f, bd / f.name)
            objs = [Path(r["source"]).stem + ".o" for r in rows if r["pin"] == pin and str(Path(r["source"]).parent) == d]
            (bd / "Kbuild").write_text("obj-m += " + " ".join(objs) + "\n")
            (bd / "Makefile").unlink(missing_ok=True)
            r = subprocess.run(["make", "-C", str(TREES[pin]), f"M={bd}", "KBUILD_MODPOST_WARN=1", "modules", "-j8"],
                               capture_output=True, text=True, env=env)
            (bd / "build.log").write_text(r.stdout + r.stderr + f"\nrc={r.returncode}\n")
            for o in objs:
                ko = bd / (o[:-2] + ".ko")
                if ko.exists():
                    st = bd / (o[:-2] + ".stripped.ko")
                    shutil.copy2(ko, st)
                    subprocess.run(["strip", "--strip-debug", str(st)], check=True)
            print(pin, d, "rc", r.returncode, sum((bd / (o[:-2] + ".ko")).exists() for o in objs), "of", len(objs))
    return 0


def module_of(r: dict) -> tuple[Path | None, Path | None]:
    """(module path, types object) for a label row, or (None, None) when it was not built."""
    pop, rid = r["population"], r["id"]
    if pop in ("B1", "B1s"):
        bd = S / "build" / r["pin"] / str(Path(r["source"]).parent).replace("/", "__")
        stem = Path(r["source"]).stem
        ko = bd / (stem + (".stripped.ko" if pop == "B1s" else ".ko"))
        return (ko if ko.exists() else None), TREES[r["pin"]] / "kernel/livepatch/core.o"
    kind, rest = rid.split(":")[1], rid.split(":", 2)[2]
    branch, cve = rest.split("/")
    if kind == "kpatch":
        d = A / "s12/results/v0.9.11-gcc-13" / branch / cve
        kos = sorted(d.glob("build/*.ko")) or sorted(d.glob("*.ko"))
    elif kind == "klp":
        kos = sorted((A / "s12/results/klp-gcc-13/6.19" / cve / "build").glob("*.ko"))
    elif kind == "klp-heldout":
        kos = sorted((A / "s12/s11-heldout/stock" / cve / "build").glob("*.ko"))
    elif kind in ("kpatch-replace", "klp-replace"):
        kos = sorted((S / "b3" / kind / cve / "build").glob("*.ko"))
    else:
        kos = []
    return (kos[0] if kos else None), TREES[branch] / "kernel/livepatch/core.o"


def run(cmd: list[str]) -> dict:
    r = subprocess.run(cmd, capture_output=True, text=True)
    for text in (r.stdout, (r.stdout.strip().splitlines() or [""])[-1]):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            continue
    return {"error": (r.stderr or r.stdout)[-300:]}


def scan() -> int:
    if hashlib.sha256(V2.read_bytes()).hexdigest() != V2_SHA:
        print("v2 is not the frozen scanner", file=sys.stderr)
        return 2
    out = S / "scan"
    out.mkdir(exist_ok=True)
    n = 0
    for r in LABELS["rows"]:
        f = out / (r["id"].replace("/", "__").replace(":", "_") + ".json")
        if f.exists():
            continue
        ko, types = module_of(r)
        if ko is None:
            continue
        res = {"id": r["id"], "module": str(ko), "module_sha256": hashlib.sha256(ko.read_bytes()).hexdigest(),
               "v1": run(["python3", str(V1), "--json", str(ko)]), "v2": run([str(PY), str(V2), "--types", str(types), str(ko)])}
        f.write_text(json.dumps(res))
        n += 1
    print("scanned", n)
    return 0


def wilson(k, n):
    if not n:
        return None
    z, p = 1.959964, k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0, c - h), 4), round(min(1, c + h), 4)]


def score() -> int:
    hz = {"SHADOW": "uses_shadow", "CALLBACKS": "has_state_callbacks", "REPLACE": "is_replace", "STATES": "uses_klp_states"}
    res = {}
    for pop in ("B1", "B1s", "B2", "B3"):
        rows = [r for r in LABELS["rows"] if r["population"] == pop]
        res[pop] = {"labelled": len(rows)}
        for ver in ("v1", "v2"):
            pairs, conj, dis, und = [], {k: Counter() for k in hz}, [], 0
            for r in rows:
                f = S / "scan" / (r["id"].replace("/", "__").replace(":", "_") + ".json")
                if not f.exists():
                    continue
                s = json.loads(f.read_text())[ver]
                if "error" in s:
                    dis.append(f"{r['id']}: error {s['error'][:80]}")
                    continue
                und += s["pre_class"] == "UNDETERMINED"
                g, p = r["class"] == "OUT_OF_SCOPE", s["pre_class"] != "SOUND"
                pairs.append((g, p))
                for k, sk in hz.items():
                    conj[k][("TP" if r[k] else "FP") if s[sk] else ("FN" if r[k] else "TN")] += 1
                if g != p or any(bool(r[k]) != bool(s[sk]) for k, sk in hz.items()):
                    dis.append(f"{r['id']}: label {r['class']} {[k for k in hz if r[k]]} scanner {s['pre_class']} "
                               f"{[k for k, sk in hz.items() if s[sk]]}")
            tp = sum(g and p for g, p in pairs)
            fn = sum(g and not p for g, p in pairs)
            fp = sum(p and not g for g, p in pairs)
            tn = sum(not g and not p for g, p in pairs)
            res[pop][ver] = {"scanned": len(pairs), "tp": tp, "fn": fn, "fp": fp, "tn": tn, "undetermined": und,
                             "recall": [tp, tp + fn, wilson(tp, tp + fn)], "specificity": [tn, tn + fp, wilson(tn, tn + fp)],
                             "conjuncts": {k: dict(v) for k, v in conj.items()}, "disagreements": dis}
    (S / "score.json").write_text(json.dumps(res, indent=1))
    for pop, v in res.items():
        print(pop, v["labelled"], {ver: {k: v[ver][k] for k in ("scanned", "tp", "fn", "fp", "tn", "undetermined")}
                                    for ver in ("v1", "v2") if ver in v})
    return 0


if __name__ == "__main__":
    raise SystemExit({"build-b1": build_b1, "scan": scan, "score": score}[sys.argv[1]]())
