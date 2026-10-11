#!/usr/bin/env python3
"""S11 diagnostic (no oracle change): for every function oracle v1.3 calls divergent between a klp-build module
and R-ind, drop R_X86_64_NONE rows on both sides, pair the remaining rows in offset order and classify each
pair whose targets differ:
  BUG_TABLE  both targets are __bug_table entries (named __bug_table_N symbol vs section+offset)
  RODATA_EQ  module target is sec:.rodata+X and the bytes there equal the reference target's bytes
  RODATA_NE  as above but the bytes differ
  OTHER      anything else
Reads /opt/atlas/s12/oracle/s11-klp-rind-v13-detail.json, writes s11-klp-rind-v13-equiv.json next to it.
Run with the oracle venv: /opt/atlas/venvs/lpfid-oracle-v11/bin/python klp_rind_equiv.py
"""
import glob
import importlib.util
import json
from collections import Counter
from pathlib import Path

A = Path("/opt/atlas")
spec = importlib.util.spec_from_file_location("oracle13", A / "lpfid/blind-reloc-oracle-v1.3.py")
O = importlib.util.module_from_spec(spec)
spec.loader.exec_module(O)
IND = A / "s12/refs-independent/6.19"
DETAIL = A / "s12/oracle/s11-klp-rind-v13-detail.json"


class RawObj(O.Obj):
    """Obj whose targets also carry where the target bytes live: label, section index, position, size."""

    def target(self, sym, addend, rtype=0, tail=4):
        label = super().target(sym, addend, rtype, tail)
        off = addend + tail if rtype in O.PC_REL else addend
        shndx = sym["st_shndx"]
        if not isinstance(shndx, int) or shndx == 0:
            return json.dumps([label, None, None, None])
        if sym["st_info"]["type"] == "STT_SECTION":
            return json.dumps([label, shndx, off, None])
        size = sym["st_size"] - off if sym["st_size"] else None
        return json.dumps([label, shndx, sym["st_value"] + off, size])

    def bytes_at(self, shndx, pos, size):
        data = self.elf.get_section(shndx).data()
        if size is None:
            end = data.find(b"\0", pos)
            size = (end - pos + 1) if end >= 0 else len(data) - pos
        return data[pos:pos + size], size


def rows(obj, loc):
    out = []
    for off, t, x in obj.relocs_in(*loc):
        if t == "0":
            continue
        out.append((off, t, json.loads(x)))
    return out


def classify(mod, ref, m, r):
    (mo, mt, (ml, ms, mp, _)), (ro, rt, (rl, rs, rp, rz)) = m, r
    if mt == rt and ml == rl:
        return "SAME"
    if "__bug_table" in ml and "__bug_table" in rl and mt == rt:
        return "BUG_TABLE"
    if ml.startswith("sec:.rodata") and mt == rt and rs is not None and ms is not None:
        rb, n = ref.bytes_at(rs, rp, rz)
        mb, _ = mod.bytes_at(ms, mp, n)
        return "RODATA_EQ" if rb == mb else "RODATA_NE"
    return "OTHER"


def main():
    det = json.loads(DETAIL.read_text())
    out, tally = [], Counter()
    for row in det["rows"]:
        if row["verdict"] != "DIVERGENT":
            continue
        mod = RawObj(Path(row["module"]))
        refs = [RawObj(Path(p)) for p in sorted(glob.glob(str(IND / row["cve"] / "**/*.o"), recursive=True))]
        mf = mod.functions()
        fres = []
        for f in row["divergent"]:
            name = f["function"]
            mr = rows(mod, mf[name])
            best = None
            for ref in refs:
                loc = ref.functions().get(name)
                if not loc:
                    continue
                rr = rows(ref, loc)
                if len(rr) != len(mr):
                    cand = {"function": name, "status": "UNALIGNED", "n_mod": len(mr), "n_ref": len(rr)}
                else:
                    kinds = Counter()
                    offs_moved = 0
                    bad = []
                    for a, b in zip(mr, rr):
                        k = classify(mod, ref, a, b)
                        kinds[k] += 1
                        offs_moved += a[0] != b[0]
                        if k in ("RODATA_NE", "OTHER"):
                            bad.append([a[1], a[2][0], b[2][0]])
                    cand = {"function": name, "status": "ALIGNED", "pairs": dict(kinds), "offsets_moved": offs_moved,
                            "unexplained": bad}
                score = (cand["status"] == "ALIGNED", -len(cand.get("unexplained", [1] * 999)))
                if best is None or score > best[0]:
                    best = (score, cand)
            fres.append(best[1] if best else {"function": name, "status": "NO_REF_FUNCTION"})
        explained = all(x["status"] == "ALIGNED" and not x["unexplained"] for x in fres)
        tally["EXPLAINED" if explained else "NOT_EXPLAINED"] += 1
        out.append({"cve": row["cve"], "explained": explained, "functions": fres})
    summ = {"divergent_modules": len(out), **tally,
            "not_explained": [o["cve"] for o in out if not o["explained"]]}
    (A / "s12/oracle/s11-klp-rind-v13-equiv.json").write_text(json.dumps({"summary": summ, "rows": out}, indent=1))
    print(json.dumps(summ, indent=1))


if __name__ == "__main__":
    main()
