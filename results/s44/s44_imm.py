#!/usr/bin/env python3
"""S44 addendum A3, validated tool: the S27 immediate check (s27_immcheck.py, the check Section 7.5.1 scores on the
1,111 constant mutants) on every shipped x86-64 module and reference pair that s44_body.py scored, plus the openEuler
and OpenAnolis pairs. Same configuration as the S27 reported operating point: frame rule off, toolchain gate off
(S27_DISABLE=T1,IMM-FRAME); the module and reference compilers are recorded per row instead.

usage: s44_imm.py [amazon|s26keep|s26re|openeuler|anolis ...] > imm-x86-2026-10-25.jsonl"""
import glob, json, os, subprocess, sys

PY = "/opt/atlas/venvs/lpfid-oracle-v11/bin/python"
IMM = os.path.expanduser("~/s44/s27_immcheck.py")
ENV = dict(os.environ, S27_ORACLE_DIR="/opt/atlas/lpfid", S27_DISABLE="T1,IMM-FRAME")
H = os.path.expanduser("~")


def run(corpus, pkg, patch, ko, refs):
    row = {"corpus": corpus, "pkg": pkg, "patch": patch, "ko": os.path.basename(ko), "ref_n": len(refs)}
    if not refs or not os.path.exists(ko):
        row["verdict"] = "NO_REFERENCE" if os.path.exists(ko) else "NO_MODULE"
    else:
        p = subprocess.run([PY, IMM, ko, *refs], capture_output=True, text=True, timeout=900, env=ENV)
        try:
            d = json.loads(p.stdout)
            row.update(verdict=d["multiset_verdict"], sequence=d["sequence_verdict"],
                       functions=d.get("functions_compared"),
                       divergent=[f.get("function") for f in d.get("divergent_functions", []) if not f["multiset_equal"]],
                       seq_divergent=[f.get("function") for f in d.get("divergent_functions", []) if not f["sequence_equal"]],
                       undecoded=d.get("undecoded_functions"),
                       mod_cc=d.get("module_compilers"), ref_cc=d.get("reference_compilers"))
        except Exception:
            row.update(verdict="ERROR", rc=p.returncode, tail=(p.stdout or p.stderr)[-400:])
    print(json.dumps(row), flush=True)


parts = sys.argv[1:] or ["amazon", "s26keep", "openeuler", "anolis"]

if "amazon" in parts:
    for corpus, res, root in (("S43", f"{H}/s43/results-x86_64.jsonl", f"{H}/s43/x86"),
                              ("S44", f"{H}/s44/results-x86_64.jsonl", f"{H}/s44/x86")):
        for line in open(res):
            r = json.loads(line)
            for m in r.get("modules", []):
                d = os.path.join(root, r["pkg"])
                refs = sorted(glob.glob(os.path.join(d, "ref", m["patch"], "**", "*.o"), recursive=True)) if m.get("patch") else []
                run(corpus, r["pkg"], m.get("patch"), os.path.join(d, "ko", m["ko"] + ".ko"), refs)

if "s26keep" in parts:
    for k in sorted(glob.glob(f"{H}/s26/results/*/keep/*/")):
        refs = sorted(glob.glob(os.path.join(k, "ref", "**", "*.o"), recursive=True))
        pkg = k.split("/results/")[1].split("/")[0]
        for ko in sorted(glob.glob(os.path.join(k, "*.ko"))):
            run("S26", pkg, os.path.basename(k.rstrip("/")), ko, refs)

if "s26re" in parts:
    # all S26 modules against the references rebuilt in ~/s44/s26re/keep (same pairing as s26_body.py)
    for rf in sorted(glob.glob(f"{H}/s26/results/*/result.json")):
        r = json.load(open(rf))
        for m in r.get("modules", []):
            k = os.path.join(H, "s44/s26re/keep", r["pkg"])
            run("S26re", r["pkg"], m["patch"], os.path.join(k, "ko", m["ko"]),
                sorted(glob.glob(os.path.join(k, "ref", m["patch"], "*.o"))))

if "openeuler" in parts:
    for d in sorted(glob.glob(f"{H}/s40/out-a3/*.x86_64/")) + sorted(glob.glob(f"{H}/s40/out/*.x86_64/")):
        kos = sorted(glob.glob(os.path.join(d, "ko", "*.ko")))
        refs = sorted(glob.glob(os.path.join(d, "ref", "**", "*.o"), recursive=True))
        for ko in kos:
            run("openEuler", os.path.basename(d.rstrip("/")), None, ko, refs)

if "anolis" in parts:
    for d in sorted(glob.glob(f"{H}/s34-anolis/results-gcc44/*/")):
        pkg = os.path.basename(d.rstrip("/"))
        try:
            if json.load(open(os.path.join(d, "result.json"))).get("status") != "SCORED":
                continue
        except Exception:
            continue
        refs = sorted(glob.glob(os.path.join(d, "refs", "**", "*.o"), recursive=True))
        for ko in sorted(glob.glob(f"{H}/s34-anolis/unpack/{pkg}/**/*.ko", recursive=True)):
            run("OpenAnolis", pkg, None, ko, refs)
