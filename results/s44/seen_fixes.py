#!/usr/bin/env python3
"""S44 addendum A2: the fixes and patched functions seen before the census (development data for v2.1).
Writes seen-fixes-2026-10-24.json: {"fixes": [...], "functions": [...], "sources": {...}}.
A fix key is the CVE identifier when the patch or module name holds one, otherwise the code name in lower case with
'.' and '&' as '-' and a trailing kernel-series suffix (-6-1, -6-12, -6-18) removed. Functions are the compared
patched functions recorded by the Amazon corpora that list them (S39, S43).
usage: seen_fixes.py <lab dir> <s26 results dir> <out.json>"""
import glob, json, os, re, sys

LAB, S26, OUT = sys.argv[1:4]
CVE = re.compile(r"CVE-\d{4}-\d+")


def key(name):
    m = CVE.search(name)
    if m:
        return m.group(0)
    k = name.lower()
    k = re.sub(r"^livepatch-", "", k)
    k = re.sub(r"\.ko$", "", k)
    k = k.replace(".", "-").replace("&", "-")
    return re.sub(r"-6-(1|12|18)$", "", k)


fixes, funcs, src = set(), set(), {}


def add(label, names, fnames=()):
    names = {key(n) for n in names if n}
    src[label] = len(names)
    fixes.update(names)
    funcs.update(fnames)


# Amazon corpora with module or patch names
names = []
for f in glob.glob(os.path.join(S26, "*", "result.json")):
    r = json.load(open(f))
    names += [m.get("patch") or m.get("ko") for m in r.get("modules", [])]
add("S26", names)
for label, p in (("S39", "s39/results-combined.jsonl"), ("S43-x86", "s43/from-tb/results-x86_64.jsonl"),
                 ("S43-aarch64", "s43/from-t4g/results-aarch64.jsonl")):
    nm, fn = [], set()
    for line in open(os.path.join(LAB, p)):
        r = json.loads(line)
        for m in r.get("modules", []):
            nm.append(m.get("patch") or m.get("ko"))
            v = m.get("v20") or {}
            fn.update(v.get("compared") or m.get("compared_functions") or [])
    add(label, nm, fn)
# stable-kernel arms, klp-build, version sweep, OpenAnolis: CVE identifiers in the recorded results
for label, pats in (("S12-load", ["s12/load-check-2026-10-08.json"]), ("loader-sweep", ["results-2026-10-10/loader-sweep.json"]),
                    ("S21", ["results-2026-10-10/s21-*.json"]), ("S11-heldout", ["s11/s11-heldout-score.json"]),
                    ("S30", ["s30/s30.json"]), ("S34", ["s34/s34-patched-functions.json"])):
    ids = set()
    for pat in pats:
        for f in glob.glob(os.path.join(LAB, pat)):
            ids.update(CVE.findall(open(f, encoding="utf-8", errors="replace").read()))
    add(label, ids)
json.dump({"fixes": sorted(fixes), "functions": sorted(funcs), "sources": src}, open(OUT, "w", newline="\n"), indent=1)
print("fixes", len(fixes), "functions", len(funcs), src)
