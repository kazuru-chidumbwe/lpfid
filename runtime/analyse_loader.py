#!/usr/bin/env python3
"""Loader baseline against the binding oracle on the same modules (manuscript 7.3, RQ2).

Inputs: the loader run (loader-baseline.json from loader-baseline.sh) and the oracle results for the same
mutants (s1-mutants JSON: rows with pin, kind, name, src, dst, overall). Parents are the control: every
unmodified parent must be accepted (LOADED_ENABLED or LOADED_NOT_LIVEPATCH).
A mutant is detected by the loader when its outcome is anything but accepted; by the oracle when its overall
verdict is DIVERGENT or LOAD_FAIL. Paired comparison: exact McNemar test on the discordant pairs.
Usage: python3 analyse_loader.py LOADER.json S1MUTANTS.json OUT.json
"""
import json
import math
import sys
from collections import Counter

ACCEPTED = {"LOADED_ENABLED", "LOADED_NOT_LIVEPATCH"}


def wilson(k: int, n: int, z: float = 1.96):
    if n == 0:
        return None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0.0, c - h), 4), round(min(1.0, c + h), 4)]


def mcnemar_exact(b: int, c: int) -> float:
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    p = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, 2 * p)


def main() -> int:
    loader = json.load(open(sys.argv[1]))["rows"]
    oracle = json.load(open(sys.argv[2]))["rows"]
    lo = {r["id"]: r for r in loader}
    parents = [r for r in loader if r["id"].startswith("parent/")]
    # a module is a livepatch when its unmodified parent loads as one (target and test modules do not)
    is_lp = {r["id"][len("parent/"):]: r["outcome"] == "LOADED_ENABLED" for r in parents}
    pairs, by_outcome, by_pin_kind = [], Counter(), Counter()
    lp_pairs, lp_outcome = [], Counter()
    for m in oracle:
        if not m.get("built") or m.get("noop"):
            continue
        mid = f"s1/{m['pin']}/{m['kind']}/{m['name']}/{m['src']}__to__{m['dst']}"
        if mid not in lo:
            continue
        ld = lo[mid]["outcome"] not in ACCEPTED
        od = m.get("overall") in ("DIVERGENT", "LOAD_FAIL")
        pairs.append((ld, od))
        if is_lp.get(f"{m['pin']}/{m['kind']}/{m['name']}"):
            lp_pairs.append((ld, od))
            lp_outcome[lo[mid]["outcome"]] += 1
        by_outcome[lo[mid]["outcome"]] += 1
        by_pin_kind[(m["pin"], m["kind"], lo[mid]["outcome"] in ACCEPTED)] += 1
    n = len(pairs)
    l_det = sum(1 for a, _ in pairs if a)
    o_det = sum(1 for _, b in pairs if b)
    b = sum(1 for a, o in pairs if o and not a)   # oracle only
    c = sum(1 for a, o in pairs if a and not o)   # loader only
    out = {
        "parents": len(parents),
        "parents_accepted": sum(1 for r in parents if r["outcome"] in ACCEPTED),
        "parents_not_accepted": [f"{r['id']} {r['outcome']}" for r in parents if r["outcome"] not in ACCEPTED],
        "mutants": n,
        "loader_outcomes": dict(by_outcome),
        "loader_accepted": n - l_det, "loader_accepted_rate": round((n - l_det) / n, 4) if n else None,
        "loader_accepted_ci95": wilson(n - l_det, n),
        "loader_detected": l_det, "loader_detected_ci95": wilson(l_det, n),
        "oracle_detected": o_det, "oracle_detected_ci95": wilson(o_det, n),
        "both": sum(1 for a, o in pairs if a and o), "oracle_only": b, "loader_only": c, "neither": sum(1 for a, o in pairs if not a and not o),
        "mcnemar_exact_p": mcnemar_exact(b, c),
        "livepatch_modules_only": {
            "mutants": len(lp_pairs), "loader_outcomes": dict(lp_outcome),
            "loader_accepted": sum(1 for a, _ in lp_pairs if not a),
            "loader_accepted_ci95": wilson(sum(1 for a, _ in lp_pairs if not a), len(lp_pairs)),
            "oracle_detected": sum(1 for _, o in lp_pairs if o),
            "oracle_only": sum(1 for a, o in lp_pairs if o and not a), "loader_only": sum(1 for a, o in lp_pairs if a and not o),
            "mcnemar_exact_p": mcnemar_exact(sum(1 for a, o in lp_pairs if o and not a), sum(1 for a, o in lp_pairs if a and not o)),
        },
        "accepted_by_pin_kind": {f"{p} {k}": {"accepted": by_pin_kind[(p, k, True)], "rejected": by_pin_kind[(p, k, False)]}
                                 for p, k in sorted({(p, k) for p, k, _ in by_pin_kind})},
    }
    json.dump(out, open(sys.argv[3], "w"), indent=1)
    print(json.dumps(out, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
