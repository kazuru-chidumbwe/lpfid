#!/usr/bin/env python3
"""S40 scorer for oracle v1.8: score every unit directory under <root> (one per <TAG>.<ARCH>, as written by
s40_pkg.sh) with v1.8 and v1.7 in one process (v1.7 = v1.8 with N1C disabled), so any verdict change is due to N1C.
Records per module the verdicts, functions compared and divergent functions. Already-scored units are skipped.
usage: s40_score18.py <oracle-v1.8.py> <root> <results.jsonl> [label]"""
import glob, importlib.util, json, os, sys, time
from pathlib import Path

ORC, ROOT, OUT = sys.argv[1:4]
LABEL = sys.argv[4] if len(sys.argv) > 4 else os.path.basename(ROOT.rstrip("/"))
spec = importlib.util.spec_from_file_location("orc18", ORC)
orc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(orc)

done = set()
if os.path.exists(OUT):
    for l in open(OUT):
        try:
            done.add(json.loads(l)["tag"])
        except Exception:
            pass


def brief(d):
    return {"overall": d["overall_verdict"], "sympos": d["sympos_verdict"],
            "funcs": d.get("functions_compared"),
            "div": sorted(f["function"] for f in d["divergent_functions"])}


for unit in sorted(glob.glob(os.path.join(ROOT, "*"))):
    tag = os.path.basename(unit)
    if not os.path.isdir(unit) or tag in done or not os.path.exists(os.path.join(unit, "PKG-DONE")):
        continue  # unfinished or failed refbuilds are listed separately, never scored
    rec = {"tag": tag, "label": LABEL, "modules": []}
    refs = sorted(glob.glob(os.path.join(unit, "ref", "cumulative", "**", "*.o"), recursive=True))
    vml = os.path.join(unit, "vmlinux")
    vml = vml if os.path.exists(vml) else None
    rec["ref_n"] = len(refs)
    for ko in sorted(glob.glob(os.path.join(unit, "ko", "*.ko"))):
        m = {"ko": os.path.basename(ko)}
        t0 = time.time()
        try:
            mod = orc.Obj(Path(ko))
            robjs = [orc.Obj(Path(p)) for p in refs]
            orc.DISABLED.discard("N1C")
            d18 = orc.compare(mod, robjs, None, vml, unit if vml else None)
            orc.DISABLED.add("N1C")
            d17 = orc.compare(mod, robjs, None, vml, unit if vml else None)
            orc.DISABLED.discard("N1C")
            m.update(v18=brief(d18), v17=brief(d17), fallbacks=d18.get("n1c_fallbacks"),
                     changed=brief(d17) != brief(d18))
            for o in [mod] + robjs:
                o.f.close()
        except Exception as e:  # noqa: BLE001
            m["error"] = f"{type(e).__name__}: {e}"[:300]
        m["secs"] = round(time.time() - t0, 1)
        rec["modules"].append(m)
    with open(OUT, "a") as f:
        f.write(json.dumps(rec) + "\n")
    print(tag, [(m.get("v18", {}).get("overall"), m.get("v17", {}).get("overall"),
                 m.get("v18", {}).get("funcs"), m.get("error")) for m in rec["modules"]], flush=True)
