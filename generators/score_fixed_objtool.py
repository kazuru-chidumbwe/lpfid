#!/usr/bin/env python3
"""S11 control scoring: the fa31c5b01-objtool rebuilds (s11_fixobjtool.py) against R-ind with oracle v1.3,
then the same equivalence classification and string-offset check as for the campaign modules.
Writes /opt/atlas/s12/oracle/s11-fixobjtool-rind-v13.json. Run with the oracle venv on the build host.
"""
import glob
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, "/opt/atlas/s12")
import klp_rind_equiv as E  # noqa: E402
import klp_rind_v13 as V  # noqa: E402

FIXRES = Path("/opt/atlas/s12/s11-fixobjtool")


def module(cve):
    k = sorted(glob.glob(str(FIXRES / cve / "build/*.ko")))
    return k[0] if k else None


def main():
    V.RES = FIXRES
    cves = sorted(p.name for p in FIXRES.iterdir() if (p / "status.json").exists()
                  and json.loads((p / "status.json").read_text()).get("ok"))
    rows, pairs, bad = [], Counter(), []
    for cve in cves:
        r = V.one(cve)
        rec = {"cve": cve, "verdict": r["verdict"], "divergence_kind": r.get("divergence_kind"), "functions": []}
        mod = E.RawObj(Path(module(cve)))
        refs = [E.RawObj(Path(p)) for p in sorted(glob.glob(str(E.IND / cve / "**/*.o"), recursive=True))]
        for f in r.get("divergent", []):
            fn = f["function"]
            mr = E.rows(mod, mod.functions()[fn])
            best = None
            for ref in refs:
                loc = ref.functions().get(fn)
                if not loc:
                    continue
                rr = E.rows(ref, loc)
                if len(rr) != len(mr):
                    cand = {"function": fn, "status": "UNALIGNED", "n_mod": len(mr), "n_ref": len(rr)}
                else:
                    k = Counter(E.classify(mod, ref, a, b) for a, b in zip(mr, rr))
                    cand = {"function": fn, "status": "ALIGNED", "pairs": dict(k)}
                if best is None or (cand["status"] == "ALIGNED" and best["status"] != "ALIGNED"):
                    best = cand
            best = best or {"function": fn, "status": "NO_REF_FUNCTION"}
            pairs.update(best.get("pairs", {}))
            if best["status"] != "ALIGNED" or best["pairs"].get("RODATA_NE") or best["pairs"].get("OTHER"):
                bad.append(f"{cve}:{fn}")
            rec["functions"].append(best)
        rows.append(rec)
    summ = {"modules": len(rows), "verdicts": dict(Counter(r["verdict"] for r in rows)), "pairs": dict(pairs),
            "not_explained": bad}
    Path("/opt/atlas/s12/oracle/s11-fixobjtool-rind-v13.json").write_text(json.dumps({"summary": summ, "rows": rows}, indent=1))
    print(json.dumps(summ, indent=1))


if __name__ == "__main__":
    main()
