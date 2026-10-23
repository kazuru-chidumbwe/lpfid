#!/usr/bin/env python3
"""S41: build replay jobs from the recorded result files on Testbed B. Writes jobs.jsonl (one oracle call per
line). Sets: s12 unmodified (kp refs), every s21 build set (kp and independent refs, 5.15, gcc 14, Debian gcc
under strict and version T1, klp-build 6.19), s2 operator mutants against both references, fixture goods, S1
fixture redirect mutants, S11 held-out klp-build subjects, string mutants and operator mutants.
usage: build_jobs.py <out.jsonl>"""
import glob, json, os, re, sys
from pathlib import Path

A = Path("/opt/atlas")
C = A / "livepatch-corpus"
TREE = {"6.1.119": C / "linux-second-pin", "6.6.47": C / "pilot-work/linux", "6.12.51": C / "linux-6.12.51",
        "5.15.173": C / "linux-5.15.173", "6.19": C / "linux-6.19", "5.16.10": C / "linux-dirtypipe"}
BRANCH_PIN = {"6.1": "6.1.119", "6.6": "6.6.47", "6.12": "6.12.51", "5.15": "5.15.173", "6.19": "6.19"}
jobs, missing = [], []


def add(set_, id_, module, refs, pin=None, t1=None):
    if not module or not os.path.exists(module) or not refs or not all(os.path.exists(r) for r in refs):
        missing.append((set_, id_))
        return
    j = {"set": set_, "id": id_, "module": module, "refs": refs}
    tree = TREE.get(pin)
    if tree and (tree / "vmlinux").exists():
        j.update(vmlinux=str(tree / "vmlinux"), modules_dir=str(tree))
    if t1:
        j["t1"] = t1
    jobs.append(j)


ld = lambda p: json.load(open(p))
rkp = ld(A / "s12/oracle/rkp.json")["rows"]
kp_refs = {(r["branch"], r["cve"]): r["refs"] for r in rkp}
for r in rkp:
    add("s12-kp", f'{r["branch"]}/{r["cve"]}', r["module"], r["refs"], r["pin"])

ind_refs = {}
for f in sorted(glob.glob(str(A / "s12/oracle/s21-*.json"))):
    stem = Path(f).stem
    d = ld(f)
    if not isinstance(d, dict) or "rows" not in d or not d["rows"] or "module" not in d["rows"][0]:
        continue
    t1 = "version" if "t1version" in stem else None
    for r in d["rows"]:
        add(stem, f'{r["branch"]}/{r["cve"]}', r["module"], r["refs"], r.get("pin") or BRANCH_PIN.get(r["branch"]), t1)
        if stem == "s21-v0.9.11-gcc-13-rind":
            ind_refs[(r["branch"], r["cve"])] = r["refs"]

goods = ld(A / "lpfid-fixtures/goods-recheck.json")["rows"]
g_refs = {f'{g["pin"]}/{g["kind"]}/{g["name"]}': g["refs"] for g in goods}
g_pin = {f'{g["pin"]}/{g["kind"]}/{g["name"]}': g["pin"] for g in goods}
for g in goods:
    add("fixture-goods", f'{g["pin"]}/{g["kind"]}/{g["name"]}', g["module"], g["refs"], g["pin"])

for i, m in enumerate(ld(A / "lpfid-fixtures/s1-mutants.json")["rows"]):
    if not m.get("built") or m.get("noop"):
        continue
    key = f'{m["pin"]}/{m["kind"]}/{m["name"]}'
    path = str(A / "lpfid-fixtures/s1mut" / m["pin"] / m["kind"] / m["name"] / f'{m["src"]}__to__{m["dst"]}.ko')
    add("s1-redirect", f'{key} {m["src"]}->{m["dst"]}', path, g_refs.get(key), m["pin"])

for row in ld(A / "s2/s2-s12-fixtures.json")["rows"]:
    for m in row["mutants"]:
        if not m.get("built") or m.get("noop") or m.get("duplicate_of"):
            continue
        mid = f'{row["id"]} {m["op"]}-{m["site_index"]}'
        if row["set"] == "s12":
            br, cve = re.split(r"__|/", row["id"], maxsplit=1)
            add("s2-kp", mid, m["path"], kp_refs.get((br, cve)), BRANCH_PIN[br])
            add("s2-ind", mid, m["path"], ind_refs.get((br, cve)), BRANCH_PIN[br])
        else:
            add("s2-fixtures", mid, m["path"], g_refs.get(row["id"]), g_pin.get(row["id"]))

h = ld(A / "s12/oracle/s11-heldout-score.json")
s_refs = {s["cve"]: s.get("refs") for s in h["subjects"]}
for s in h["subjects"]:
    for kind in ("stock", "fixed"):
        if s.get(f"{kind}_built"):
            add(f"s11-heldout-{kind}", s["cve"], s[kind], s.get("refs"), "6.19")
for m in h["mutants"]:
    add("s11-string-mutants", f'{m["cve"]} {m["function"]} {m["site"]}', m["module"], s_refs.get(m["cve"]), "6.19")
for m in h["operator_mutants"]:
    if not m.get("built") or m.get("noop") or m.get("duplicate_of"):
        continue
    cve = re.search(r"(CVE-\d+-\d+)", m["path"]).group(1)
    add("s11-op-mutants", f'{m["path"].split("heldout-opmutants/")[-1]}', m["path"], s_refs.get(cve), "6.19")

with open(sys.argv[1], "w") as f:
    for j in jobs:
        f.write(json.dumps(j) + "\n")
from collections import Counter
print("jobs by set:", dict(Counter(j["set"] for j in jobs)))
print("missing inputs:", len(missing), dict(Counter(s for s, _ in missing)))
