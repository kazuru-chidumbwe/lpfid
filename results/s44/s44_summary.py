#!/usr/bin/env python3
"""S44 reduction (internal/S44-PREREG-2026-10-24.md with addenda A1 and A2). One results file per architecture.
Strata: D (patch name holds CVE-2026-31431, or v2.1 compares memcpy_sglist), H-new (fix key not in the seen-fix list),
H-seen (the rest of H). Per stratum and architecture: false alarms per distinct fix (A1, primary), per module and per
patched function; detection per operator on mutants of CONSISTENT parents; support; site availability; v2.0/v2.1
differences; MDUP exposure; every miss. Wilson 95%; package and fix bootstraps, 2,000 resamples, seed 44.
usage: s44_summary.py <seen-fixes.json> <out.json> <arch>=<results.jsonl> [<arch>=<results.jsonl> ...]"""
import json, math, random, re, sys
from collections import Counter, defaultdict

SEEN_P, OUT = sys.argv[1:3]
RUNS = [a.split("=", 1) for a in sys.argv[3:]]
seen = json.load(open(SEEN_P))
SEEN_FIX, SEEN_FN = set(seen["fixes"]), set(seen["functions"])
CVE = re.compile(r"CVE-\d{4}-\d+")
SCAFFOLD = {"init_module", "cleanup_module", "__pfx_init_module", "__pfx_cleanup_module"}
DET = ("DIVERGENT", "LOAD_FAIL")


def key(name):
    """seen_fixes.py rule: CVE identifier, else the code name without its kernel-series suffix."""
    m = CVE.search(name)
    if m:
        return m.group(0)
    k = re.sub(r"\.ko$", "", re.sub(r"^livepatch-", "", name.lower())).replace(".", "-").replace("&", "-")
    return re.sub(r"-6-(1|12|18)$", "", k)


def wilson(k, n, z=1.959964):
    if n == 0:
        return None
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [round(max(0.0, (c - h) / d), 4), round(min(1.0, (c + h) / d), 4)]


def boot(units, B=2000, seed=44):
    """units: cluster -> (k, n). Percentile 95% interval of the pooled rate over resampled clusters."""
    cl = list(units.values())
    if not cl or sum(n for _, n in cl) == 0:
        return None
    rng = random.Random(seed)
    rates = []
    for _ in range(B):
        s = [cl[rng.randrange(len(cl))] for _ in cl]
        n = sum(x[1] for x in s)
        if n:
            rates.append(sum(x[0] for x in s) / n)
    rates.sort()
    return [round(rates[int(0.025 * len(rates))], 4), round(rates[min(len(rates) - 1, int(0.975 * len(rates)))], 4)]


def stratum(m):
    name = m.get("patch") or m["ko"]
    if "CVE-2026-31431" in name or "CVE-2026-31431" in m["ko"] or "memcpy_sglist" in (m["v21"].get("compared") or []):
        return "D"
    return "H-seen" if key(name) in SEEN_FIX else "H-new"


out = {"protocol": "internal/S44-PREREG-2026-10-24.md", "archs": {}}
for arch, path in RUNS:
    pk = Counter()
    pk_fail = []
    mods = defaultdict(list)            # stratum -> module records
    for line in open(path):
        r = json.loads(line)
        if "modules" not in r:
            pk[r.get("status", "?")] += 1
            pk_fail.append({"pkg": r["pkg"], "status": r.get("status"), "reason": r.get("reason", "")[:200]})
            continue
        pk["scored"] += 1
        for m in r["modules"]:
            if "v21" not in m:
                pk["module-" + (m.get("status") or "?").split(":")[0]] += 1
                pk_fail.append({"pkg": r["pkg"], "module": m["ko"], "status": m.get("status")})
                continue
            m["_pkg"] = r["pkg"]
            mods[stratum(m)].append(m)
    A = {"packages": dict(pk), "not_scored": pk_fail, "strata": {}}
    for st in ("H-new", "H-seen", "D", "all"):
        ms = [m for s in ("H-new", "H-seen", "D") for m in mods[s]] if st == "all" else mods[st]
        if not ms:
            A["strata"][st] = {"modules": 0}
            continue
        fx = defaultdict(list)
        for m in ms:
            fx[key(m.get("patch") or m["ko"])].append(m)
        fa_fix = sum(1 for v in fx.values() if any(m["v21"]["overall"] != "CONSISTENT" for m in v))
        fa_mod = [m for m in ms if m["v21"]["overall"] != "CONSISTENT"]
        nfun = sum(len([f for f in (m["v21"].get("compared") or []) if f not in SCAFFOLD]) for m in ms)
        dfun = sum(len(m["v21"].get("div") or []) for m in ms)
        by_pkg, by_fix = defaultdict(lambda: [0, 0]), defaultdict(lambda: [0, 0])
        for m in ms:
            a = int(m["v21"]["overall"] != "CONSISTENT")
            for d, k in ((by_pkg, m["_pkg"]), (by_fix, key(m.get("patch") or m["ko"]))):
                d[k][0] += a
                d[k][1] += 1
        S = {"modules": len(ms), "packages": len({m["_pkg"] for m in ms}), "fixes": len(fx),
             "fix_keys": sorted(fx),
             "fa_fixes": [fa_fix, len(fx), wilson(fa_fix, len(fx))],
             "fa_modules": [len(fa_mod), len(ms), wilson(len(fa_mod), len(ms)),
                            boot({k: tuple(v) for k, v in by_pkg.items()}), boot({k: tuple(v) for k, v in by_fix.items()})],
             "fa_functions": [dfun, nfun, wilson(dfun, nfun)],
             "alarms": [{"pkg": m["_pkg"], "ko": m["ko"], "v21": m["v21"]["overall"], "div": m["v21"].get("div"),
                         "sympos": m["v21"].get("sympos")} for m in fa_mod],
             "mdup_modules": [{"pkg": m["_pkg"], "ko": m["ko"], "pairings": m["v21"].get("mdup")} for m in ms if m["v21"].get("mdup")],
             "function_new_modules": sum(1 for m in ms if not (set(m["v21"].get("compared") or []) - SCAFFOLD) & SEEN_FN),
             "detection": {}, "sites": {}, "excluded": {}, "v20_v21_differ": [], "misses": []}
        ops = sorted({op for m in ms for op in m.get("ops", {})})
        for op in ops:
            k = n = 0
            dp, df = defaultdict(lambda: [0, 0]), defaultdict(lambda: [0, 0])
            avail = sum(1 for m in ms if m.get("ops", {}).get(op, {}).get("eligible"))
            S["sites"][op] = [avail, len(ms)]
            exc = Counter()
            for m in ms:
                if m["v21"]["overall"] != "CONSISTENT":
                    continue
                for x in m.get("ops", {}).get(op, {}).get("mutants", []):
                    if "excluded" in x:
                        exc[x["excluded"].split(" of ")[0].split(":")[0]] += 1
                        continue
                    if "v21" not in x:
                        continue
                    hit = int(x["v21"]["overall"] in DET)
                    k += hit
                    n += 1
                    for d, kk in ((dp, m["_pkg"]), (df, key(m.get("patch") or m["ko"]))):
                        d[kk][0] += hit
                        d[kk][1] += 1
                    if x["v21"]["overall"] != x["v20"]["overall"]:
                        S["v20_v21_differ"].append({"pkg": m["_pkg"], "ko": m["ko"], "op": op, "site": x["site_index"],
                                                    "v20": x["v20"]["overall"], "v21": x["v21"]["overall"], "div": x["v21"].get("div")})
                    if not hit:
                        S["misses"].append({"pkg": m["_pkg"], "ko": m["ko"], "op": op, "site_index": x["site_index"],
                                            "site": x["site"], "v21": x["v21"]["overall"]})
            S["detection"][op] = [k, n, wilson(k, n), boot({a: tuple(b) for a, b in dp.items()}),
                                  boot({a: tuple(b) for a, b in df.items()})]
            S["excluded"][op] = dict(exc)
        for m in ms:
            if m["v21"]["overall"] != m["v20"]["overall"]:
                S["v20_v21_differ"].append({"pkg": m["_pkg"], "ko": m["ko"], "op": "parent",
                                            "v20": m["v20"]["overall"], "v21": m["v21"]["overall"]})
        A["strata"][st] = S
    out["archs"][arch] = A
json.dump(out, open(OUT, "w", newline="\n"), indent=1)
for arch, A in out["archs"].items():
    print(f"== {arch}: packages {A['packages']}")
    for st, S in A["strata"].items():
        if not S.get("modules"):
            print(f"  {st}: no modules")
            continue
        print(f"  {st}: modules {S['modules']} pkgs {S['packages']} fixes {S['fixes']} | FA fixes {S['fa_fixes']} "
              f"modules {S['fa_modules'][:3]} functions {S['fa_functions']} | mdup {len(S['mdup_modules'])} "
              f"function-new {S['function_new_modules']} | differ {len(S['v20_v21_differ'])} misses {len(S['misses'])}")
        print("    det " + ", ".join(f"{op} {d[0]}/{d[1]}" for op, d in S["detection"].items()))
        print("    sites " + ", ".join(f"{op} {a}/{b}" for op, (a, b) in S["sites"].items()))
