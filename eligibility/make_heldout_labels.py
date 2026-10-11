#!/usr/bin/env python3
"""S6b: write the held-out labels (S6B-PREREG-2026-10-11.md) from source and fix diffs only, before any build or scan.
Output: /opt/atlas/lpfid/s6b/heldout-labels.json (copied to lab/s6b/ and committed with its SHA-256).
"""
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, "/opt/atlas/lpfid")
import label_source as L  # noqa: E402

A = Path("/opt/atlas")
C = A / "livepatch-corpus"
OUT = A / "lpfid/s6b"
OUT.mkdir(parents=True, exist_ok=True)
B1_PINS = {"6.12.51": C / "linux-6.12.51", "6.19": C / "linux-6.19"}
B1_DIRS = ("samples/livepatch", "tools/testing/selftests/livepatch/test_modules")
NEW_SOURCES = {"test_klp_syscall.c", "test_klp_kprobe.c"}


def blob(p: Path) -> str:
    data = p.read_bytes()
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


rows, excluded = [], []
for pin, tree in B1_PINS.items():
    for d in B1_DIRS:
        for f in sorted((tree / d).glob("*.c")):
            lab = L.label_c(f)
            rid = f"B1:{pin}:{d}/{f.name}"
            if "excluded" in lab:
                excluded.append({"id": rid, "reason": lab["excluded"]})
                continue
            rows.append({"id": rid, "population": "B1", "pin": pin, "source": f"{d}/{f.name}", "git_blob": blob(f),
                         "new_source": f.name in NEW_SOURCES, **lab})
            rows.append({**rows[-1], "id": rid.replace("B1:", "B1s:"), "population": "B1s"})

fixes = []
for st in sorted((A / "s12/results/v0.9.11-gcc-13").glob("*/*/status.json")):
    s = json.loads(st.read_text())
    if s.get("ok") and (st.parent / "fix.patch").exists():
        fixes.append(("B2", f"kpatch:{st.parent.parent.name}/{st.parent.name}", st.parent / "fix.patch", 0))
for st in sorted((A / "s12/results/klp-gcc-13/6.19").glob("*/status.json")):
    if json.loads(st.read_text()).get("ok"):
        fixes.append(("B2", f"klp:6.19/{st.parent.name}", st.parent / "fix.patch", 0))
import subprocess  # noqa: E402
hp = OUT / "patches-heldout-h"
hp.mkdir(parents=True, exist_ok=True)
for h in json.loads((A / "s12/out/6.19/heldout-h.json").read_text())["heldout"]:
    pf = hp / f"{h['cve']}.patch"
    if not pf.exists():
        pf.write_text(subprocess.run(["git", "-C", str(A / "s12/stable619"), "show", "--format=", "--no-color",
                                      h["stable_sha"]], capture_output=True, text=True, check=True).stdout)
    fixes.append(("B2", f"klp-heldout:6.19/{h['cve']}", pf, 0))
kp612 = sorted(st.parent for st in (A / "s12/results/v0.9.11-gcc-13/6.12").glob("*/status.json")
               if json.loads(st.read_text()).get("ok"))[:5]
for d in kp612:
    fixes.append(("B3", f"kpatch-replace:6.12/{d.name}", d / "fix.patch", 1))
klp = sorted(st.parent for st in (A / "s12/results/klp-gcc-13/6.19").glob("*/status.json")
             if json.loads(st.read_text()).get("ok"))[:5]
for d in klp:
    fixes.append(("B3", f"klp-replace:6.19/{d.name}", d / "fix.patch", 1))
for pop, rid, patch, flag in fixes:
    if not patch.exists():
        excluded.append({"id": f"{pop}:{rid}", "reason": "no fix.patch"})
        continue
    rows.append({"id": f"{pop}:{rid}", "population": pop, "source": str(patch), "patch_sha256":
                 hashlib.sha256(patch.read_bytes()).hexdigest(), "replace_flag": flag, **L.label_patch(patch, flag)})

doc = {"prereg": "internal/S6B-PREREG-2026-10-11.md", "labeller": "lab/s6b/label_source.py",
       "labeller_sha256": hashlib.sha256(Path("/opt/atlas/lpfid/label_source.py").read_bytes()).hexdigest(),
       "rows": rows, "excluded": excluded}
p = OUT / "heldout-labels.json"
p.write_text(json.dumps(doc, indent=1))
from collections import Counter  # noqa: E402
print(hashlib.sha256(p.read_bytes()).hexdigest())
print(Counter((r["population"], r["class"]) for r in rows), len(excluded), "excluded")
