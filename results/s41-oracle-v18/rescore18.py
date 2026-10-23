#!/usr/bin/env python3
"""S41: replay recorded oracle calls under v1.8 and v1.7 in one process (v1.7 = v1.8 with N1C disabled, shown
identical on 19 modules). Loads each module and its references once and compares twice, so any verdict change is
due to N1C alone. Jobs are JSON lines: {set, id, module, refs, vmlinux?, modules_dir?, t1?}.
usage: rescore18.py <oracle-v1.8.py> <jobs.jsonl> <out.jsonl> <shard> <nshards>"""
import importlib.util, json, os, sys, time, traceback
from pathlib import Path

ORC, JOBS, OUT, SHARD, NSH = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
spec = importlib.util.spec_from_file_location("orc18", ORC)
orc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(orc)

done = set()
if os.path.exists(OUT):
    for l in open(OUT):
        try:
            r = json.loads(l)
            done.add((r["set"], r["id"]))
        except Exception:
            pass


def brief(d):
    return {"overall": d["overall_verdict"], "multiset": d["multiset_verdict"], "sequence": d["sequence_verdict"],
            "sympos": d["sympos_verdict"], "div": sorted(f["function"] for f in d["divergent_functions"])}


with open(JOBS) as jf, open(OUT, "a") as of:
    for i, line in enumerate(jf):
        if i % NSH != SHARD:
            continue
        j = json.loads(line)
        if (j["set"], j["id"]) in done:
            continue
        rec = {"set": j["set"], "id": j["id"]}
        t0 = time.time()
        try:
            if j.get("t1"):
                os.environ["LPFID_T1"] = j["t1"]
            else:
                os.environ.pop("LPFID_T1", None)
            mod = orc.Obj(Path(j["module"]))
            refs = [orc.Obj(Path(p)) for p in j["refs"]]
            orc.DISABLED.discard("N1C")
            d18 = orc.compare(mod, refs, None, j.get("vmlinux"), j.get("modules_dir"))
            orc.DISABLED.add("N1C")
            d17 = orc.compare(mod, refs, None, j.get("vmlinux"), j.get("modules_dir"))
            orc.DISABLED.discard("N1C")
            rec.update(v17=brief(d17), v18=brief(d18), fallbacks=d18.get("n1c_fallbacks"),
                       changed=brief(d17) != brief(d18))
            for o in [mod] + refs:
                o.f.close()
        except Exception as e:  # noqa: BLE001
            rec["error"] = f"{type(e).__name__}: {e}"[:300]
        rec["secs"] = round(time.time() - t0, 2)
        of.write(json.dumps(rec) + "\n")
        of.flush()
