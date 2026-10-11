#!/usr/bin/env python3
"""S6b: check label_source.py against the 60 hand-made S6 labels before it labels any held-out module."""
import json, subprocess, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import label_source as L
REPO = "/opt/atlas/s12/stable619"
KP = Path("/opt/atlas/livepatch-real/kpatch-int")  # the S6 campaign copies
rows = json.load(open("/opt/atlas/livepatch-real/labels.json"))["rows"]
agree, out = 0, []
with tempfile.TemporaryDirectory() as td:
    for r in rows:
        src = r["source"]
        if src.startswith("dynup/kpatch"):
            lab = L.label_patch(KP / src.split("test/integration/", 1)[1], 0)
        else:
            path, tag = src.split("@")
            d = Path(td) / tag / Path(path).parent
            if not d.exists():
                d.mkdir(parents=True)
                for f in subprocess.run(["git", "-C", REPO, "ls-tree", "--name-only", f"{tag}:{Path(path).parent}"],
                                        capture_output=True, text=True, check=True).stdout.split():
                    if f.endswith(".c"):
                        (d / f).write_bytes(subprocess.run(["git", "-C", REPO, "show", f"{tag}:{Path(path).parent}/{f}"],
                                                           capture_output=True, check=True).stdout)
            lab = L.label_c(d / Path(path).name)
        keys = ("SHADOW", "CALLBACKS", "REPLACE", "STATES", "class")
        same = all(lab.get(k) == r[k] for k in keys)
        agree += same
        if not same:
            out.append({"id": r["id"], "hand": {k: r[k] for k in keys}, "mechanical": lab})
print(json.dumps({"rows": len(rows), "agree": agree, "disagree": out}, indent=1))
