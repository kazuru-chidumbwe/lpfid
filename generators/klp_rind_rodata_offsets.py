#!/usr/bin/env python3
"""S11 diagnostic: for each klp-build module whose R-ind divergence klp_rind_equiv.py could not explain, find
where the referenced bytes sit in the module's .rodata and report the distance between the relocation's
target and the nearest exact copy of the reference string or object (delta 0 would mean a correct pointer).
Run with the oracle venv on the build host after klp_rind_equiv.py.
"""
import glob
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, "/opt/atlas/s12")
import klp_rind_equiv as E  # noqa: E402

eq = json.load(open("/opt/atlas/s12/oracle/s11-klp-rind-v13-equiv.json"))
deltas, out = Counter(), []
for row in eq["rows"]:
    if row["explained"]:
        continue
    cve = row["cve"]
    mod = E.RawObj(Path(glob.glob(f"/opt/atlas/s12/results/klp-gcc-13/6.19/{cve}/build/*.ko")[0]))
    refs = [E.RawObj(Path(p)) for p in sorted(glob.glob(str(E.IND / cve / "**/*.o"), recursive=True))]
    for f in row["functions"]:
        fn = f["function"]
        if not f.get("unexplained"):
            continue
        for ref in refs:
            loc = ref.functions().get(fn)
            if not loc:
                continue
            mr, rr = E.rows(mod, mod.functions()[fn]), E.rows(ref, loc)
            if len(mr) != len(rr):
                continue
            for a, b in zip(mr, rr):
                k = E.classify(mod, ref, a, b)
                if k not in ("RODATA_NE", "OTHER"):
                    continue
                mdata = mod.elf.get_section(a[2][1]).data()
                rec = {"cve": cve, "function": fn, "site": hex(a[0]), "module_target": a[2][0], "ref_target": b[2][0]}
                if b[2][1] is None:
                    rec.update(kind="REF_EXTERNAL", module_bytes=mdata[a[2][2]:a[2][2] + 48].hex())
                    deltas["external"] += 1
                else:
                    rb, n = ref.bytes_at(b[2][1], b[2][2], b[2][3])
                    hits = [i for i in range(len(mdata) - n + 1) if mdata[i:i + n] == rb]
                    d = min((a[2][2] - h for h in hits), key=abs) if hits else None
                    rec.update(kind="RODATA", addend=hex(a[2][2]), copies=[hex(h) for h in hits], delta=d)
                    deltas[d] += 1
                out.append(rec)
json.dump({"deltas": {str(k): v for k, v in deltas.items()}, "rows": out},
          open("/opt/atlas/s12/oracle/s11-klp-rind-v13-rodata-offsets.json", "w"), indent=1)
for r in out:
    print(r["cve"], r["function"], r["site"], r.get("addend"), r.get("copies"), r.get("delta"), r["kind"])
print("DELTAS", dict(deltas))
