#!/usr/bin/env python3
"""S40 scorer: score one openEuler SysCare hotpatch .ko against the cumulative reference objects, oracle v1.7.
usage: s40_score.py <oracle.py> <python> <pkg_out_dir> <results.jsonl>"""
import sys, os, glob, json, subprocess
ORC, PY, OUTDIR, RESULTS = sys.argv[1:5]
tag = os.path.basename(OUTDIR.rstrip("/"))
refs = sorted(glob.glob(os.path.join(OUTDIR, "ref", "cumulative", "**", "*.o"), recursive=True))
vml = os.path.join(OUTDIR, "vmlinux"); hv = os.path.exists(vml)
rec = {"tag": tag, "ref_n": len(refs), "n_ko": 0, "scored": 0, "false_alarms": 0, "errors": 0, "modules": []}
for ko in sorted(glob.glob(os.path.join(OUTDIR, "ko", "*.ko"))):
    rec["n_ko"] += 1
    cmd = [PY, ORC, ko] + refs + (["--vmlinux", vml, "--modules-dir", OUTDIR] if hv else [])
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=2400)
    try:
        d = json.loads(r.stdout)
    except Exception:
        d = {"overall_verdict": "ERROR", "_err": (r.stderr or "")[-200:]}
    jd = os.path.join(os.path.dirname(os.path.abspath(RESULTS)), "oracle-json"); os.makedirs(jd, exist_ok=True)
    with open(os.path.join(jd, "%s__%s.json" % (tag, os.path.basename(ko))), "w") as f:
        json.dump(d, f, indent=1)
    v = d.get("overall_verdict", "ERROR")
    m = {"ko": os.path.basename(ko), "verdict": v, "sympos": d.get("sympos_verdict"),
         "funcs_compared": d.get("functions_compared"),
         "divergent": [f.get("function") for f in d.get("divergent_functions", [])]}
    if v == "ERROR":
        rec["errors"] += 1
    else:
        rec["scored"] += 1
        if v not in ("CONSISTENT", "INCONCLUSIVE", "INCONCLUSIVE_TOOLCHAIN", "NO_COMMON_FUNCTIONS"):
            rec["false_alarms"] += 1
    rec["modules"].append(m)
with open(RESULTS, "a") as f:
    f.write(json.dumps(rec) + "\n")
print("%s ko=%d scored=%d FA=%d ref_n=%d funcs=%s"
      % (tag, rec["n_ko"], rec["scored"], rec["false_alarms"], rec["ref_n"],
         [m.get("funcs_compared") for m in rec["modules"]]))
